import time
from dataclasses import dataclass
from typing import Optional
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import redis_client


@dataclass
class MessageEnvelope:
    encrypted_content: bytes
    iv: bytes
    session_id: str  # Identifies which session key was used
    timestamp: int


class SecureMessageService:
    def __init__(self):
        self.active_sessions: dict[str, bytes] = {}  # session_id -> shared_secret
        self.session_store: dict[str, bytes] = {}  # Persistent storage of session keys

    def generate_keypair(self) -> tuple[dh.DHPrivateKey, dh.DHPublicKey]:
        """Generate a new DH keypair for a session."""
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key = parameters.generate_private_key()
        return private_key, private_key.public_key()

    def derive_shared_secret(self, private_key: dh.DHPrivateKey, peer_public_key: dh.DHPublicKey) -> bytes:
        """Derive the shared secret using HKDF."""
        shared_key = private_key.exchange(peer_public_key)
        # Derive a proper encryption key from the shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        )
        return hkdf.derive(shared_key)

    def encrypt_message(self, message: str, session_id: str) -> MessageEnvelope:
        """Encrypt a message using the session's shared secret."""
        shared_secret = self.active_sessions.get(session_id) or self.session_store.get(session_id)
        if not shared_secret:
            raise ValueError("No shared secret found for this session")

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Pad message to AES block size
        padded_message = message.encode()
        padded_message += b' ' * (-len(padded_message) % 16)

        encrypted_content = encryptor.update(padded_message) + encryptor.finalize()

        return MessageEnvelope(
            encrypted_content=encrypted_content,
            iv=iv,
            session_id=session_id,
            timestamp=int(time.time())
        )

    def decrypt_message(self, envelope: MessageEnvelope) -> str:
        """Decrypt a message using the stored session key."""
        shared_secret = self.active_sessions.get(envelope.session_id) or self.session_store.get(envelope.session_id)
        if not shared_secret:
            raise ValueError("Session key not found")

        cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(envelope.iv))
        decryptor = cipher.decryptor()

        decrypted = decryptor.update(envelope.encrypted_content) + decryptor.finalize()
        return decrypted.rstrip().decode()

    def store_session(self, session_id: str, shared_secret: bytes):
        """Store session key for later message decryption."""
        self.session_store[session_id] = shared_secret
        redis_client.store_session(session_id, shared_secret)

    def load_session(self, session_id: str) -> Optional[bytes]:
        """Load a previously stored session key."""
        return self.session_store.get(session_id)