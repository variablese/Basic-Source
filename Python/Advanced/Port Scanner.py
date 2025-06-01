import socket
import threading
import time
import random
import logging
import struct
import argparse
import re
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, UDP, sr1, RandShort, conf
from typing import List, Tuple, Optional

# Setup logging for error handling
logging.basicConfig(filename='port_scanner_errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
CONFIG = {
    'timeout': 1.0,  # Socket timeout (seconds)
    'threads': 50,   # Max concurrent threads
    'retry_interval': 0.1,  # Delay between retries
    'max_retries': 2,  # Retry attempts for failed scans
    'common_ports': [21, 22, 23, 25, 80, 443, 445, 3389],  # Common ports
    'service_signatures': {
        21: {'banner': r'220.*FTP', 'name': 'FTP'},
        22: {'banner': r'SSH-', 'name': 'SSH'},
        80: {'banner': r'HTTP/1\.', 'name': 'HTTP'},
        443: {'banner': r'HTTP/1\.', 'name': 'HTTPS'},
        445: {'banner': r'SMB', 'name': 'SMB'},
        3389: {'banner': r'RDP', 'name': 'RDP'}
    },
    'ttl_range': (30, 255),  # Random TTL for evasion
    'delay_range': (0.01, 0.1)  # Random delay for anti-IDS
}

# Obfuscation: Fake payload to confuse IDS
def _obfuscated_payload(): return ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(10, 20)))

# Anti-IDS: Randomize packet timing
def random_delay():
    return random.uniform(*CONFIG['delay_range'])

# TCP SYN scan (stealth)
def tcp_syn_scan(target: str, port: int) -> Tuple[int, str]:
    try:
        conf.verb = 0  # Suppress Scapy verbosity
        src_port = RandShort()
        pkt = IP(dst=target, ttl=random.randint(*CONFIG['ttl_range'])) / TCP(sport=src_port, dport=port, flags='S')
        response = sr1(pkt, timeout=CONFIG['timeout'], retry=CONFIG['max_retries'])
        if response and response.haslayer(TCP):
            if response[TCP].flags & 0x12:  # SYN-ACK
                return port, 'open'
            elif response[TCP].flags & 0x14:  # RST-ACK
                return port, 'closed'
        return port, 'filtered'
    except Exception as e:
        logging.error(f"TCP SYN scan failed for {target}:{port}: {e}")
        return port, 'error'

# UDP scan
def udp_scan(target: str, port: int) -> Tuple[int, str]:
    try:
        conf.verb = 0
        pkt = IP(dst=target, ttl=random.randint(*CONFIG['ttl_range'])) / UDP(sport=RandShort(), dport=port) / _obfuscated_payload()
        response = sr1(pkt, timeout=CONFIG['timeout'], retry=CONFIG['max_retries'])
        if response is None:
            return port, 'open|filtered'  # No response often means open or filtered
        elif response.haslayer(UDP):
            return port, 'open'
        elif response.haslayer(ICMP) and response[ICMP].type == 3 and response[ICMP].code in [1, 2, 3, 9, 10, 13]:
            return port, 'closed'
        return port, 'filtered'
    except Exception as e:
        logging.error(f"UDP scan failed for {target}:{port}: {e}")
        return port, 'error'

# Service detection via banner grabbing
def detect_service(target: str, port: int, protocol: str = 'tcp') -> Optional[str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
        sock.settimeout(CONFIG['timeout'])
        sock.connect((target, port))
        if protocol == 'tcp':
            sock.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n' + _obfuscated_payload().encode())
            banner = sock.recv(1024).decode(errors='ignore')
            for port_sig, info in CONFIG['service_signatures'].items():
                if port == port_sig and re.search(info['banner'], banner, re.IGNORECASE):
                    return info['name']
            return banner[:50] if banner else 'Unknown'
        sock.close()
    except Exception as e:
        logging.error(f"Service detection failed for {target}:{port}: {e}")
        return None

# OS fingerprinting via TTL and TCP window size
def os_fingerprint(target: str) -> str:
    try:
        pkt = IP(dst=target) / TCP(flags='S')
        response = sr1(pkt, timeout=CONFIG['timeout'], retry=CONFIG['max_retries'])
        if response and response.haslayer(IP) and response.haslayer(TCP):
            ttl = response[IP].ttl
            win_size = response[TCP].window
            if ttl <= 64 and win_size > 40000:
                return 'Linux/Unix'
            elif ttl <= 128 and win_size < 20000:
                return 'Windows'
            elif ttl > 128:
                return 'Solaris/AIX'
            return f'Unknown (TTL: {ttl}, Win: {win_size})'
        return 'Unknown'
    except Exception as e:
        logging.error(f"OS fingerprinting failed for {target}: {e}")
        return 'Unknown'

# Main scanning function
def scan_ports(target: str, ports: List[int], protocol: str = 'tcp', stealth: bool = True) -> List[Tuple[int, str, Optional[str]]]:
    results = []
    with ThreadPoolExecutor(max_workers=CONFIG['threads']) as executor:
        if protocol == 'tcp' and stealth:
            future_to_port = {executor.submit(tcp_syn_scan, target, port): port for port in ports}
        elif protocol == 'udp':
            future_to_port = {executor.submit(udp_scan, target, port): port for port in ports}
        else:
            future_to_port = {executor.submit(lambda t, p: (p, 'open' if socket.socket().connect_ex((t, p)) == 0 else 'closed'), target, port): port for port in ports}
        
        for future in future_to_port:
            port, status = future.result()
            time.sleep(random_delay())  # Anti-IDS timing
            service = detect_service(target, port, protocol) if status.startswith('open') else None
            results.append((port, status, service))
    
    return sorted(results, key=lambda x: x[0])

# CLI interface
def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner for Defensive Research")
    parser.add_argument('target', help="Target IP or hostname")
    parser.add_argument('-p', '--ports', default='1-1024', help="Port range (e.g., 1-1000 or 80,443)")
    parser.add_argument('-t', '--protocol', choices=['tcp', 'udp'], default='tcp', help="Protocol to scan")
    parser.add_argument('-s', '--stealth', action='store_true', help="Enable stealth SYN scanning")
    args = parser.parse_args()

    try:
        # Parse port range
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p) for p in args.ports.split(',')]
        
        # Resolve target
        target = socket.gethostbyname(args.target)
        
        # OS fingerprinting
        os_type = os_fingerprint(target)
        print(f"[*] OS Fingerprint: {os_type}")
        
        # Scan ports
        print(f"[*] Scanning {target} ({args.protocol.upper()})...")
        results = scan_ports(target, ports, args.protocol, args.stealth)
        
        # Display results
        for port, status, service in results:
            print(f"Port {port}: {status}" + (f" ({service})" if service else ""))
        
        _obfuscated_payload()  # Oobfuscation: Call junk code
    
    except Exception as e:
        logging.error(f"Main scan failed: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
