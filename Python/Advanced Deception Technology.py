from flask import Flask, request, jsonify
import socket
import threading
import random
import logging
from werkzeug.serving import WSGIRequestHandler
import json
import base64
import os
import time
from datetime import datetime
import psutil
import win32api
import win32process
import win32con
from PIL import ImageGrab
import pyautogui
from cryptography.fernet import Fernet

class AdvancedDeceptionSystem:
    def __init__(self):
        self.app = Flask(__name__)
        self.services = {
            'ftp': {'port': 21, 'handler': self._handle_ftp},
            'http': {'port': 80, 'handler': self._handle_http},
            'ssh': {'port': 22, 'handler': self._handle_ssh},
            'mysql': {'port': 3306, 'handler': self._handle_mysql},
            'smtp': {'port': 25, 'handler': self._handle_smtp},
            'rdp': {'port': 3389, 'handler': self._handle_rdp}
        }
        
        # Initialize deception components
        self.deception_layers = {
            'network': self._network_deception,
            'system': self._system_deception,
            'application': self._application_deception
        }
        
        # Initialize encryption
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        
        # Initialize logging
        self._setup_logging()
        
        # Initialize attacker database
        self.attacker_db = {}
        self.suspicious_ips = set()
        
        # Initialize deception state
        self.deception_state = {
            'active_sessions': {},
            'decoy_files': {},
            'fake_processes': {},
            'network_lures': {}
        }

    def _setup_logging(self):
        """Setup encrypted logging system"""
        log_dir = Path('threat_logs')
        log_dir.mkdir(exist_ok=True)
        logging.basicConfig(
            filename=log_dir / 'threat_intel.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _network_deception(self, client, ip):
        """Network layer deception"""
        # Simulate network delays
        delay = random.uniform(0.1, 0.5)
        time.sleep(delay)
        
        # Simulate network conditions
        if random.random() < 0.1:
            return self._simulate_network_error(client)
        
        return True

    def _system_deception(self, client, ip):
        """System layer deception"""
        # Create decoy processes
        if random.random() < 0.3:
            self._create_decoy_process(ip)
        
        # Create decoy files
        if random.random() < 0.2:
            self._create_decoy_file(ip)
        
        return True

    def _application_deception(self, client, ip):
        """Application layer deception"""
        # Simulate application behavior
        if random.random() < 0.4:
            self._simulate_application_error(client)
        
        return True

    def _create_decoy_process(self, ip):
        """Create decoy process"""
        process_name = f"system_service_{random.randint(1000, 9999)}.exe"
        self.deception_state['fake_processes'][process_name] = {
            'ip': ip,
            'created': datetime.now(),
            'type': 'system'
        }
        self.logger.info(f"Created decoy process {process_name} for {ip}")

    def _create_decoy_file(self, ip):
        """Create decoy file"""
        file_name = f"important_data_{random.randint(1000, 9999)}.txt"
        self.deception_state['decoy_files'][file_name] = {
            'ip': ip,
            'created': datetime.now(),
            'type': 'file'
        }
        self.logger.info(f"Created decoy file {file_name} for {ip}")

    def _simulate_network_error(self, client):
        """Simulate network error"""
        try:
            client.send(b"Connection reset by peer\r\n")
            client.close()
            return True
        except:
            return False

    def _simulate_application_error(self, client):
        """Simulate application error"""
        try:
            client.send(b"500 Internal Server Error\r\n")
            time.sleep(2)
            return True
        except:
            return False

    def _handle_ftp(self, client, ip):
        """Enhanced FTP handler"""
        if not self._network_deception(client, ip):
            return
        
        client.send(b"220 FTP Honeypot Server Ready\r\n")
        
        while True:
            data = client.recv(1024)
            if not data:
                break
                
            command = data.decode().strip()
            self.logger.info(f"FTP command from {ip}: {command}")
            
            # Deception logic
            if command.startswith('LIST'):
                self._send_decoy_directory(client)
            elif command.startswith('RETR'):
                self._send_decoy_file(client)
            
            client.send(b"200 OK\r\n")
        
        client.close()

    def _handle_http(self, client, ip):
        """Enhanced HTTP handler"""
        if not self._network_deception(client, ip):
            return
        
        request = client.recv(4096)
        self.logger.info(f"HTTP request from {ip}:\n{request.decode()}")
        
        # Extract metadata
        self._extract_metadata(ip, request)
        
        # Send deceptive response
        response = self._generate_deceptive_response(ip)
        client.send(response.encode())
        
        client.close()

    def _extract_metadata(self, ip, request):
        """Extract metadata from HTTP request"""
        try:
            # Extract user agent and other headers
            headers = request.decode().split('\r\n')
            for header in headers:
                if 'User-Agent:' in header:
                    self.attacker_db[ip]['metadata']['browser'] = header.split(':')[1].strip()
                    break
        except:
            pass

    def _generate_deceptive_response(self, ip):
        """Generate deceptive HTTP response"""
        if ip in self.suspicious_ips:
            return self._generate_error_response()
        
        return (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<html><body><h1>Welcome to our server</h1></body></html>"
        )

    def _store_threat_data(self, ip, data):
        """Store threat data with encryption"""
        encrypted_data = self.cipher_suite.encrypt(
            json.dumps(data).encode()
        )
        
        # Store in memory
        self.threat_db['ips'][ip] = encrypted_data
        
        # Store in file
        with open(f'threat_data/{ip}.dat', 'wb') as f:
            f.write(encrypted_data)
        
        self.logger.info(f"Stored encrypted threat data for {ip}")

    def start_all(self):
        """Start all deception services"""
        for name, config in self.services.items():
            thread = threading.Thread(
                target=self._start_service,
                args=(name, config['port'], config['handler'])
            )
            thread.daemon = True
            thread.start()

    def _start_service(self, name, port, handler):
        """Start individual deception service"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        
        while True:
            client, addr = sock.accept()
            client_ip = addr[0]
            self._log_attempt(client_ip, name)
            
            handler_thread = threading.Thread(
                target=handler,
                args=(client, client_ip)
            )
            handler_thread.start()

# Web interface for monitoring
@app.route('/deception/stats')
def deception_stats():
    return jsonify({
        'total_attackers': len(attacker_db),
        'active_sessions': len(deception_state['active_sessions']),
        'decoy_files': len(deception_state['decoy_files']),
        'fake_processes': len(deception_state['fake_processes']),
        'suspicious_ips': list(suspicious_ips)
    })

if __name__ == "__main__":
    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    deception_system = AdvancedDeceptionSystem()
    deception_system.start_all()
    app.run(port=5000)
