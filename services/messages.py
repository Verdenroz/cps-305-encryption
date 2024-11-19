import os
import time
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

from redis_client import SecureRedisClient, StoredMessage


class MessageService:
    def __init__(self, redis_client: SecureRedisClient):
        self.redis = redis_client
        self.active_sessions = {}  # client_id -> (private_key, public_key)
        self.shared_secrets = {}  # session_id -> shared_secret

    def generate_dh_keypair(self) -> Tuple[int, int]:
        """Generate DH keypair for the server."""
        # Use the same prime as frontend
        p = int(
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
            16)
        g = 2

        # Generate private key
        private_key = int.from_bytes(os.urandom(32), 'big')
        # Calculate public key
        public_key = pow(g, private_key, p)

        return private_key, public_key

    async def initialize_secure_channel(self, client_id: str, client_public_key: str) -> Tuple[str, str]:
        """Initialize secure channel with client and return session ID."""
        private_key, public_key = self.generate_dh_keypair()

        # Store keypair
        self.active_sessions[client_id] = (private_key, public_key)

        # Compute shared secret
        p = int(
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
            16)

        client_public_key_int = int(client_public_key)
        shared_secret_int = pow(client_public_key_int, private_key, p)

        # Derive final key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        )
        shared_secret = hkdf.derive(shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, 'big'))

        # Create and store session
        session_id = f"session_{client_id}_{int(time.time())}"
        self.shared_secrets[session_id] = shared_secret
        await self.redis.store_session(session_id, client_id, shared_secret)

        return session_id, str(public_key)

    async def handle_message(self, client_id: str, message_data: dict):
        """Handle incoming encrypted message."""
        encrypted_content = base64.b64decode(message_data['encrypted'])
        iv = base64.b64decode(message_data['iv'])
        session_id = message_data['session_id']
        recipient_id = message_data['recipient']

        # Store message
        await self.redis.store_message(
            StoredMessage(
                sender_id=client_id,
                recipient_id=recipient_id,
                encrypted_content=encrypted_content,
                iv=iv,
                session_id=session_id,
                timestamp=int(time.time())
            )
        )

        return {"status": "success"}

    async def get_messages(self, client_id: str, peer_id: Optional[str] = None) -> list[dict]:
        """Retrieve messages between client and peer or all messages for the client."""
        messages = await self.redis.get_messages(client_id, peer_id)

        # Encode byte fields to base64
        encoded_messages = []
        for message in messages:
            encoded_messages.append({
                'sender_id': message.sender_id,
                'recipient_id': message.recipient_id,
                'encrypted_content': base64.b64encode(message.encrypted_content).decode('utf-8'),
                'iv': base64.b64encode(message.iv).decode('utf-8'),
                'session_id': message.session_id,
                'timestamp': message.timestamp
            })

        return encoded_messages
