import hashlib
import secrets
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt_message(message: str, key: bytes) -> dict:
    """Encrypt message using AES-256-CBC with integrity check."""
    # Generate IV
    iv = secrets.token_bytes(16)
    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Calculate hash before encryption
    message_hash = hashlib.sha256(message.encode()).hexdigest()
    # Encrypt
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    # Encode for transmission
    return {
        'iv': b64encode(iv).decode('utf-8'),
        'ciphertext': b64encode(ct_bytes).decode('utf-8'),
        'hash': message_hash
    }


def decrypt_message(encrypted_data: dict, key: bytes) -> str:
    """Decrypt message and verify integrity."""
    # Decode from base64
    iv = b64decode(encrypted_data['iv'])
    ciphertext = b64decode(encrypted_data['ciphertext'])
    received_hash = encrypted_data['hash']

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # Verify hash
    calculated_hash = hashlib.sha256(decrypted).hexdigest()
    if calculated_hash != received_hash:
        raise ValueError("Message integrity check failed")

    return decrypted.decode()
