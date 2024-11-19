import base64
import json
import os
import time
from typing import Optional
from dataclasses import dataclass
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from redis import asyncio as aioredis


@dataclass
class StoredMessage:
    sender_id: str
    recipient_id: str
    encrypted_content: bytes
    iv: bytes
    session_id: str
    timestamp: int

load_dotenv()

class SecureRedisClient:
    def __init__(self):
        self.redis = aioredis.Redis(
            connection_pool=aioredis.ConnectionPool(
                host=os.environ['REDIS_HOST'],
                port=int(os.environ['REDIS_PORT']),
                username=os.environ['REDIS_USERNAME'],
                password=os.environ['REDIS_PASSWORD'],
                max_connections=10000
            ),
            single_connection_client=True,
        )
        # Keys for different types of data
        self.sessions_key = "secure_msg:sessions:"
        self.messages_key_prefix = "secure_msg:messages:"

        # Master key for encrypting session keys
        # In production, this should be securely managed (e.g., using a KMS)
        self.master_key = Fernet(os.environ.get('MASTER_KEY', Fernet.generate_key()))

    async def store_session(self, session_id: str, client_id: str, shared_secret: bytes):
        """Store an encrypted session key in Redis."""
        # Encrypt the session key before storing
        encrypted_secret = self.master_key.encrypt(shared_secret)

        session_data = {
            'client_id': client_id,
            'created_at': int(time.time()),
            'secret': base64.b64encode(encrypted_secret).decode('utf-8')
        }

        # Store session data
        await self.redis.hset(
            f"{self.sessions_key}{client_id}",
            session_id,
            json.dumps(session_data)
        )

        # Set expiry for 30 days
        await self.redis.expire(f"{self.sessions_key}{client_id}", 2592000)

    async def get_session(self, session_id: str, client_id: str) -> Optional[bytes]:
        """Retrieve and decrypt a session key from Redis."""
        session_data = await self.redis.hget(
            f"{self.sessions_key}{client_id}",
            session_id
        )

        if not session_data:
            return None

        try:
            data = json.loads(session_data)
            encrypted_secret = base64.b64decode(data['secret'])
            return self.master_key.decrypt(encrypted_secret)
        except Exception as e:
            print(f"Error decrypting session key: {e}")
            return None

    async def store_message(self, message: StoredMessage):
        """Store encrypted message in Redis."""
        message_data = {
            'sender': message.sender_id,
            'recipient': message.recipient_id,
            'encrypted_content': base64.b64encode(message.encrypted_content).decode('utf-8'),
            'iv': base64.b64encode(message.iv).decode('utf-8'),
            'session_id': message.session_id,
            'timestamp': message.timestamp
        }

        # Create conversation key - sort IDs to ensure consistent key
        conv_key = f"{self.messages_key_prefix}{min(message.sender_id, message.recipient_id)}:{max(message.sender_id, message.recipient_id)}"

        # Store message
        await self.redis.rpush(conv_key, json.dumps(message_data))

        # Set expiry for 30 days
        await self.redis.expire(conv_key, 2592000)

    async def get_messages(self, client_id: str, peer_id: Optional[str] = None) -> list[StoredMessage]:
        """Retrieve messages between client and peer or all messages for the client."""
        if peer_id:
            # Get messages for specific conversation
            conv_key = f"{self.messages_key_prefix}{min(client_id, peer_id)}:{max(client_id, peer_id)}"
            messages = await self.redis.lrange(conv_key, 0, -1)
        else:
            # Get all messages for client
            pattern = f"{self.messages_key_prefix}*{client_id}*"
            keys = await self.redis.keys(pattern)
            messages = []
            for key in keys:
                msgs = await self.redis.lrange(key, 0, -1)
                messages.extend(msgs)

        # Convert stored messages to StoredMessage objects
        result = []
        for msg in messages:
            data = json.loads(msg.decode())
            result.append(StoredMessage(
                sender_id=data['sender'],
                recipient_id=data['recipient'],
                encrypted_content=base64.b64decode(data['encrypted_content']),
                iv=base64.b64decode(data['iv']),
                session_id=data['session_id'],
                timestamp=data['timestamp']
            ))

        return result
