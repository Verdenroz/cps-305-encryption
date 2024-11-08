import os
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

    async def cleanup_client(self, client_id: str):
        """Remove all data for a client."""
        await self.redis.hdel(self.public_keys_key, client_id)
        await self.redis.hdel(self.private_keys_key, client_id)

        # Clean up shared secrets
        all_secrets = await self.redis.hgetall(self.shared_secrets_key)
        for key in all_secrets:
            key = key.decode()
            if key.startswith(f"{client_id}:") or key.endswith(f":{client_id}"):
                await self.redis.hdel(self.shared_secrets_key, key)
