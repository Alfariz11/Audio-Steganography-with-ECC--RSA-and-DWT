import os
import hashlib
from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import HKDF

class ECCCrypto:
    """
    Implements secure ECC encryption using ECIES-style key agreement.
    Uses ECDH to derive a shared secret and HKDF to generate an AES key.
    """
    def __init__(self, curve='P-256'):
        self.curve = curve
        self.key = None
        self.generate_key()
    
    def generate_key(self):
        """Generates a new ECC key pair."""
        self.key = ECC.generate(curve=self.curve)
        return self.key
    
    def get_public_key(self):
        """Exports public key in PEM format."""
        if not self.key:
            self.generate_key()
        return self.key.public_key().export_key(format='PEM')
    
    def get_private_key(self):
        """Exports private key in PEM format."""
        if not self.key:
            self.generate_key()
        return self.key.export_key(format='PEM')
    
    def load_key(self, key_str, is_private=True):
        """Loads an ECC key from a string."""
        try:
            self.key = ECC.import_key(key_str)
            return True
        except Exception as e:
            print(f"Error loading ECC key: {str(e)}")
            return False

    def encrypt_session_key(self, session_key, recipient_public_key_pem):
        """
        Encrypts a session key using the recipient's public key via ECDH.
        Returns: (ephemeral_public_key_bytes, encrypted_session_key, iv, tag)
        """
        recipient_key = ECC.import_key(recipient_public_key_pem)
        
        # 1. Generate ephemeral key pair
        ephemeral_key = ECC.generate(curve=self.curve)
        ephemeral_pub_bytes = ephemeral_key.public_key().export_key(format='DER')
        
        # 2. ECDH Key Agreement
        # shared_point = ephemeral_private_key * recipient_public_key
        shared_secret = self._derive_shared_secret(ephemeral_key, recipient_key)
        
        # 3. KDF to derive encryption key for the session key
        # We use HKDF to derive a 256-bit key
        derived_key = HKDF(shared_secret, 32, b'', SHA256)
        
        # 4. Encrypt the session key using AES-GCM
        cipher = AES.new(derived_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(session_key)
        
        return ephemeral_pub_bytes, ciphertext, cipher.nonce, tag

    def decrypt_session_key(self, ephemeral_pub_bytes, encrypted_session_key, nonce, tag):
        """
        Decrypts the session key using the private key.
        """
        if not self.key or not self.key.has_private():
            raise ValueError("Private key is required for decryption")
            
        ephemeral_pub_key = ECC.import_key(ephemeral_pub_bytes)
        
        # 1. ECDH Key Agreement
        # shared_point = private_key * ephemeral_public_key
        shared_secret = self._derive_shared_secret(self.key, ephemeral_pub_key)
        
        # 2. KDF to derive the same encryption key
        derived_key = HKDF(shared_secret, 32, b'', SHA256)
        
        # 3. Decrypt the session key
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        try:
            session_key = cipher.decrypt_and_verify(encrypted_session_key, tag)
            return session_key
        except ValueError:
            raise ValueError("ECC decryption failed: MAC check failed")

    def _derive_shared_secret(self, private_key, public_key):
        """Performs ECDH and returns the x-coordinate as the shared secret."""
        # Shared point = d * Q
        shared_point = public_key.pointQ * private_key.d
        # Convert x-coordinate to bytes
        return int(shared_point.x).to_bytes(32, 'big')

    def hash_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        return hashlib.sha256(message).digest()
