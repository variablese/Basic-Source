# Description: A Python suite for AES encryption, password vaults, 2FA QR codes, and PGP/GPG email, for defensive research under ACRP-2025-05-30-001.
# Features: AES-256-GCM encryption, secure vault with PBKDF2, TOTP QR codes, PGP/GPG email signing/encryption.
# Obfuscation: Minimal, with randomized salts and nonces.
# Historical Trivia: AES was standardized in 2001 (NIST); PGP debuted in 1991, revolutionizing secure comms.

import os
import sys
import argparse
import base64
import json
import logging
import secrets
import getpass
import qrcode
import gnupg
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

# Setup logging
logging.basicConfig(filename='crypto_suite_errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
CONFIG = {
    'vault_file': Path.home() / '.secure_vault.json',
    'key_length': 32,  # AES-256
    'nonce_length': 12,  # GCM nonce
    'salt_length': 16,
    'iterations': 100000,
    'gpg_home': Path.home() / '.gnupg',
    'qr_output': '2fa_qr.png'
}

# --- AES Encryption Utilities ---
class AESUtil:
    @staticmethod
    def generate_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """Derive AES-256 key from password using PBKDF2HMAC."""
        try:
            if salt is None:
                salt = secrets.token_bytes(CONFIG['salt_length'])
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=CONFIG['key_length'],
                salt=salt,
                iterations=CONFIG['iterations'],
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            return key, salt
        except Exception as e:
            logging.error(f"Key generation failed: {e}")
            raise

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
        """Encrypt data with AES-256-GCM."""
        try:
            nonce = secrets.token_bytes(CONFIG['nonce_length'])
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return ciphertext + encryptor.tag, nonce
        except Exception as e:
            logging.error(f"AES encryption failed: {e}")
            raise

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """Decrypt AES-256-GCM data."""
        try:
            tag = ciphertext[-16:]  # GCM tag is 16 bytes
            ciphertext = ciphertext[:-16]
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidKey as e:
            logging.error(f"AES decryption failed: Invalid key - {e}")
            raise
        except Exception as e:
            logging.error(f"AES decryption failed: {e}")
            raise

# --- Secure Password Vault ---
class PasswordVault:
    def __init__(self):
        self.vault_file = CONFIG['vault_file']
        self.vault = {}

    def load_vault(self, password: str) -> bool:
        """Load and decrypt vault."""
        try:
            if not self.vault_file.exists():
                return True
            with open(self.vault_file, 'rb') as f:
                data = json.load(f)
            key, _ = AESUtil.generate_key(password, base64.b64decode(data['salt']))
            encrypted = base64.b64decode(data['data'])
            nonce = base64.b64decode(data['nonce'])
            decrypted = AESUtil.decrypt(encrypted, key, nonce)
            self.vault = json.loads(decrypted.decode())
            return True
        except Exception as e:
            logging.error(f"Vault load failed: {e}")
            return False

    def save_vault(self, password: str):
        """Encrypt and save vault."""
        try:
            key, salt = AESUtil.generate_key(password)
            data = json.dumps(self.vault).encode()
            encrypted, nonce = AESUtil.encrypt(data, key)
            vault_data = {
                'salt': base64.b64encode(salt).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'data': base64.b64encode(encrypted).decode()
            }
            with open(self.vault_file, 'w') as f:
                json.dump(vault_data, f)
        except Exception as e:
            logging.error(f"Vault save failed: {e}")
            raise

    def add_entry(self, service: str, username: str, password: str):
        """Add a password entry."""
        try:
            self.vault[service] = {'username': username, 'password': password}
        except Exception as e:
            logging.error(f"Add entry failed: {e}")
            raise

    def get_entry(self, service: str) -> dict:
        """Retrieve a password entry."""
        return self.vault.get(service, {})

# --- 2FA QR-Code Generator ---
class TwoFactorAuth:
    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a TOTP secret."""
        return base64.b32encode(secrets.token_bytes(20)).decode()

    @staticmethod
    def generate_qr_code(service: str, username: str, secret: str):
        """Generate a TOTP QR code."""
        try:
            totp_uri = f'otpauth://totp/{service}:{username}?secret={secret}&issuer={service}'
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')
            img.save(CONFIG['qr_output'])
            return secret
        except Exception as e:
            logging.error(f"QR code generation failed: {e}")
            raise

# --- Secure Email (PGP/GPG Interface) ---
class SecureEmail:
    def __init__(self):
        self.gpg = gnupg.GPG(gnupghome=CONFIG['gpg_home'], options=['--pinentry-mode', 'loopback'])

    def generate_key(self, name: str, email: str, passphrase: str):
        """Generate a GPG key pair."""
        try:
            input_data = self.gpg.gen_key_input(
                name_real=name,
                name_email=email,
                passphrase=passphrase,
                key_type='RSA',
                key_length=2048
            )
            key = self.gpg.gen_key(input_data)
            return key.fingerprint
        except Exception as e:
            logging.error(f"GPG key generation failed: {e}")
            raise

    def encrypt_email(self, recipient: str, message: str, sign: bool = False, passphrase: str = None) -> str:
        """Encrypt and optionally sign an email."""
        try:
            encrypted = self.gpg.encrypt(message, recipient, sign=sign, passphrase=passphrase)
            if not encrypted.ok:
                raise Exception(encrypted.status)
            return str(encrypted)
        except Exception as e:
            logging.error(f"Email encryption failed: {e}")
            raise

    def decrypt_email(self, encrypted_message: str, passphrase: str) -> str:
        """Decrypt an email."""
        try:
            decrypted = self.gpg.decrypt(encrypted_message, passphrase=passphrase)
            if not decrypted.ok:
                raise Exception(decrypted.status)
            return str(decrypted)
        except Exception as e:
            logging.error(f"Email decryption failed: {e}")
            raise

# --- CLI Interface ---
def main():
    parser = argparse.ArgumentParser(description="Secure Crypto Suite for Defensive Research")
    subparsers = parser.add_subparsers(dest='command')

    # AES Encryption
    aes_parser = subparsers.add_parser('aes', help="AES encryption utilities")
    aes_parser.add_argument('--encrypt', help="Text to encrypt")
    aes_parser.add_argument('--decrypt', help="Base64-encoded ciphertext to decrypt")
    aes_parser.add_argument('--password', required=True, help="Encryption password")

    # Password Vault
    vault_parser = subparsers.add_parser('vault', help="Password vault management")
    vault_parser.add_argument('--add', nargs=3, metavar=('service', 'username', 'password'), help="Add a password entry")
    vault_parser.add_argument('--get', help="Get a password entry by service")
    vault_parser.add_argument('--password', required=True, help="Vault master password")

    # 2FA QR Code
    tfa_parser = subparsers.add_parser('2fa', help="2FA QR code generator")
    tfa_parser.add_argument('--service', required=True, help="Service name")
    tfa_parser.add_argument('--username', required=True, help="Username")

    # Secure Email
    email_parser = subparsers.add_parser('email', help="PGP/GPG email tools")
    email_parser.add_argument('--generate-key', nargs=3, metavar=('name', 'email', 'passphrase'), help="Generate GPG key")
    email_parser.add_argument('--encrypt', nargs=2, metavar=('recipient', 'message'), help="Encrypt email")
    email_parser.add_argument('--decrypt', help="Decrypt email")
    email_parser.add_argument('--passphrase', help="GPG key passphrase")
    email_parser.add_argument('--sign', action='store_true', help="Sign email")

    args = parser.parse_args()

    try:
        if args.command == 'aes':
            aes_util = AESUtil()
            password = args.password
            if args.encrypt:
                key, salt = aes_util.generate_key(password)
                ciphertext, nonce = aes_util.encrypt(args.encrypt.encode(), key)
                print(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode()}")
                print(f"Nonce (base64): {base64.b64encode(nonce).decode()}")
                print(f"Salt (base64): {base64.b64encode(salt).decode()}")
            elif args.decrypt:
                key, _ = aes_util.generate_key(password, base64.b64decode(input("Salt (base64): ")))
                nonce = base64.b64decode(input("Nonce (base64): "))
                ciphertext = base64.b64decode(args.decrypt)
                plaintext = aes_util.decrypt(ciphertext, key, nonce)
                print(f"Plaintext: {plaintext.decode()}")

        elif args.command == 'vault':
            vault = PasswordVault()
            if not vault.load_vault(args.password):
                print("Invalid master password")
                sys.exit(1)
            if args.add:
                service, username, password = args.add
                vault.add_entry(service, username, password)
                vault.save_vault(args.password)
                print(f"Added entry for {service}")
            elif args.get:
                entry = vault.get_entry(args.get)
                if entry:
                    print(f"Service: {args.get}, Username: {entry['username']}, Password: {entry['password']}")
                else:
                    print(f"No entry for {args.get}")

        elif args.command == '2fa':
            tfa = TwoFactorAuth()
            secret = tfa.generate_totp_secret()
            tfa.generate_qr_code(args.service, args.username, secret)
            print(f"TOTP Secret: {secret}")
            print(f"QR Code saved to: {CONFIG['qr_output']}")

        elif args.command == 'email':
            email = SecureEmail()
            if args.generate_key:
                name, email_addr, passphrase = args.generate_key
                fingerprint = email.generate_key(name, email_addr, passphrase)
                print(f"Generated GPG key: {fingerprint}")
            elif args.encrypt:
                recipient, message = args.encrypt
                encrypted = email.encrypt_email(recipient, message, args.sign, args.passphrase)
                print(f"Encrypted message:\n{encrypted}")
            elif args.decrypt:
                decrypted = email.decrypt_email(args.decrypt, args.passphrase)
                print(f"Decrypted message:\n{decrypted}")

    except Exception as e:
        logging.error(f"Command execution failed: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

# **WARNING: FOR EDUCATIONAL PURPOSES ONLY. MISUSE MAY VIOLATE CFAA, EU CYBERCRIME DIRECTIVE, OR OTHER LAWS. USE RESPONSIBLY IN ISRL-7 LAB.**
