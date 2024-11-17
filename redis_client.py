import base64
import json
import os
import time
from base64 import b64decode, b64encode
from typing import Optional

from dotenv import load_dotenv
from redis import asyncio as aioredis

load_dotenv()

class RedisClient:
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
        self.public_keys_key = "secure_msg:public_keys"
        self.private_keys_key = "secure_msg:private_keys"
        self.shared_secrets_key = "secure_msg:shared_secrets"
        self.messages_key_prefix = "secure_msg:messages:"

    async def store_public_key(self, client_id: str, public_key: int):
        """Store public key in Redis."""
        await self.redis.hset(self.public_keys_key, client_id, str(public_key))

    async def get_public_key(self, client_id: str) -> Optional[int]:
        """Retrieve public key from Redis."""
        key = await self.redis.hget(self.public_keys_key, client_id)
        return int(key) if key else None

    async def store_private_key(self, client_id: str, private_key: int):
        """Store private key in Redis."""
        await self.redis.hset(self.private_keys_key, client_id, str(private_key))

    async def get_private_key(self, client_id: str) -> Optional[int]:
        """Retrieve private key from Redis."""
        key = await self.redis.hget(self.private_keys_key, client_id)
        return int(key) if key else None

    async def store_shared_secret(self, client_id: str, peer_id: str, shared_secret: bytes):
        """Store shared secret in Redis."""
        key = f"{client_id}:{peer_id}"
        await self.redis.hset(
            self.shared_secrets_key,
            key,
            b64encode(shared_secret).decode()
        )
        await self.redis.hexpire(self.shared_secrets_key,3600, key)

    async def get_shared_secret(self, client_id: str, peer_id: str) -> Optional[bytes]:
        """Retrieve shared secret from Redis."""
        key = f"{client_id}:{peer_id}"
        secret = await self.redis.hget(self.shared_secrets_key, key)
        return b64decode(secret) if secret else None

    async def store_message(self, sender_id: str, recipient_id: str, encrypted_message: dict):
        """Store encrypted message in Redis."""
        message_data = {
            'sender': sender_id,
            'recipient': recipient_id,
            'timestamp': int(time.time()),
            'message': encrypted_message
        }
        # Create conversation key - sort IDs to ensure consistent key regardless of sender/recipient
        conv_key = f"{self.messages_key_prefix}{min(sender_id, recipient_id)}:{max(sender_id, recipient_id)}"
        # Encode the shared_key to base64 string
        message_data['message']['shared_key'] = base64.b64encode(message_data['message']['shared_key']).decode('utf-8')

        # Store message
        await self.redis.rpush(conv_key, json.dumps(message_data))
        print(f"Stored message in {conv_key}")
        # Expire conversation key after 30 days
        await self.redis.expire(conv_key, 2592000)

    async def get_messages(self, client_id: str, peer_id: Optional[str] = None) -> list[dict]:
        """Retrieve messages between client and peer or all messages for the client."""
        if peer_id:
            # Create conversation key using sorted IDs for consistency
            conv_key = f"{self.messages_key_prefix}{min(client_id, peer_id)}:{max(client_id, peer_id)}"
            # Get all messages for this conversation
            messages = await self.redis.lrange(conv_key, 0, -1)
            return [json.loads(msg.decode()) for msg in messages]
        else:
            # Retrieve all conversation keys for the client
            pattern = f"{self.messages_key_prefix}*{client_id}*"
            keys = await self.redis.keys(pattern)
            all_messages = []
            for key in keys:
                messages = await self.redis.lrange(key, 0, -1)
                all_messages.extend([json.loads(msg.decode()) for msg in messages])
            return all_messages