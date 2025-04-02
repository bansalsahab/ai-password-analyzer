from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import hashlib
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    passwords = db.relationship('Password', backref='owner', lazy='dynamic', cascade="all, delete-orphan")
    
    @staticmethod
    def generate_salt():
        """Generate a random salt for password hashing"""
        return binascii.hexlify(os.urandom(32)).decode()
    
    @staticmethod
    def hash_password(password, salt, iterations=100000):
        """
        Hash a password using PBKDF2 with HMAC-SHA256
        """
        dk = hashlib.pbkdf2_hmac('sha256', 
                                 password.encode(), 
                                 salt.encode(), 
                                 iterations,
                                 dklen=64)
        return binascii.hexlify(dk).decode()
    
    @staticmethod
    def derive_key(password, salt, iterations=100000):
        """
        Derive encryption key from password using PBKDF2
        """
        dk = hashlib.pbkdf2_hmac('sha256', 
                                 password.encode(),
                                 salt.encode(),
                                 iterations,
                                 dklen=32)  # 32 bytes for AES-256
        return dk
    
    def set_password(self, password):
        """
        Set password hash and salt
        """
        self.salt = self.generate_salt()
        self.password_hash = self.hash_password(password, self.salt)
    
    def verify_password(self, password):
        """
        Verify password against stored hash
        """
        return self.password_hash == self.hash_password(password, self.salt)
    
    def encrypt_password(self, plain_password):
        """
        Encrypt a password using derived key from master password
        """
        try:
            # We need to use the master password for encryption, not the password hash
            # Use the session master password from the current context
            from flask import session
            master_password = session.get('master_password')
            
            if not master_password:
                print("No master password in session for encryption")
                return None
                
            # Generate a random IV for AES encryption
            iv = os.urandom(16)
            
            # Derive encryption key from master password
            key = self.derive_key(master_password, self.salt)
            
            # Create cipher object and encrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plain_password.encode(), AES.block_size))
            
            # Return IV + ciphertext
            return base64.b64encode(iv + ciphertext).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return None
    
    def decrypt_password(self, encrypted_password, master_password):
        """
        Decrypt a password using derived key from master password
        """
        try:
            if not master_password:
                print("No master password provided for decryption")
                return None
                
            # Derive encryption key
            key = self.derive_key(master_password, self.salt)
            
            # Decode from base64
            data = base64.b64decode(encrypted_password.encode('utf-8'))
            
            # Extract IV (first 16 bytes)
            iv = data[:16]
            ciphertext = data[16:]
            
            # Create cipher object and decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

class Password(db.Model):
    __tablename__ = 'passwords'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    website = db.Column(db.String(100))
    label = db.Column(db.String(100))
    score = db.Column(db.Integer)
    entropy = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self, include_password=False, master_password=None):
        """
        Convert password record to dictionary for API responses
        """
        result = {
            'id': self.id,
            'website': self.website,
            'label': self.label,
            'score': self.score,
            'entropy': self.entropy,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat()
        }
        
        if include_password and master_password:
            try:
                # Use a more robust approach that will attempt decryption
                decrypted = self.owner.decrypt_password(self.encrypted_password, master_password)
                
                if decrypted:
                    result['password'] = decrypted
                else:
                    print(f"Failed to decrypt password (ID: {self.id}) - decrypt_password returned None")
            except Exception as e:
                print(f"Exception during password decryption (ID: {self.id}): {str(e)}")
                # Don't add password to result if decryption fails
        
        return result 