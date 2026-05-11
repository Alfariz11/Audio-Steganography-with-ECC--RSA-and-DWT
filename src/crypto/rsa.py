import hashlib
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256

class RSACrypto:
    """
    Implements RSA for Digital Signatures.
    Used to verify the authenticity of the encrypted steganography payload.
    """
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.key = None
        self.generate_key()
    
    def generate_key(self):
        """Generates a new RSA key pair."""
        self.key = RSA.generate(self.key_size)
        return self.key
    
    def get_public_key(self):
        """Exports public key in PEM format."""
        if not self.key:
            self.generate_key()
        return self.key.publickey().export_key().decode('utf-8')
    
    def get_private_key(self):
        """Exports private key in PEM format."""
        if not self.key:
            self.generate_key()
        return self.key.export_key().decode('utf-8')
    
    def load_key(self, key_str, is_private=True):
        """Loads an RSA key from a string."""
        try:
            self.key = RSA.import_key(key_str)
            return True
        except Exception as e:
            print(f"Error loading RSA key: {str(e)}")
            return False
    
    def sign_data(self, data):
        """
        Signs data using the private key.
        Returns the signature bytes.
        """
        if not self.key or not self.key.has_private():
            raise ValueError("Private key is required for signing")
            
        h = SHA256.new(data)
        signature = pkcs1_15.new(self.key).sign(h)
        return signature
    
    def verify_signature(self, data, signature, public_key_pem=None):
        """
        Verifies the signature of the data using the public key.
        Returns True if valid, False otherwise.
        """
        if public_key_pem:
            key = RSA.import_key(public_key_pem)
        else:
            key = self.key.publickey()
            
        h = SHA256.new(data)
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def hash_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        return hashlib.sha256(message).digest()
