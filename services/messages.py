from typing import Optional

from starlette.websockets import WebSocket, WebSocketState

from redis_client import RedisClient
from services.aes import encrypt_message
from services.keys import generate_keypair, generate_shared_secret


class MessageService:
    def __init__(self, redis: RedisClient):
        self.redis = redis
        self.connections: dict[str: WebSocket] = {}

    async def initialize_secure_channel(self, client_id: str) -> tuple[int, int]:
        """Initialize secure channel by generating and storing keypair if not already present."""
        # Check if keys already exist
        private_key = await self.redis.get_private_key(client_id)
        public_key = await self.redis.get_public_key(client_id)

        if private_key and public_key:
            print(f"Keys already exist for client {client_id}")
            return private_key, public_key

        # Generate and store new keypair
        private_key, public_key = generate_keypair()
        await self.redis.store_private_key(client_id, private_key)
        await self.redis.store_public_key(client_id, public_key)
        print(f"Generated new keys for client {client_id}")
        return private_key, public_key

    async def establish_shared_secret(self, client_id: str, peer_id: str) -> bytes:
        """Establish shared secret between two clients."""
        # Get our private key and peer's public key
        private_key = await self.redis.get_private_key(client_id)
        peer_public_key = await self.redis.get_public_key(peer_id)
        if not private_key or not peer_public_key:
            raise ValueError("Missing keys for secure channel")

        # Generate and store shared secret
        shared_secret = generate_shared_secret(private_key, peer_public_key)
        await self.redis.store_shared_secret(client_id, peer_id, shared_secret)
        return shared_secret

    async def handle_message(self, sender_id: str, message_data: dict, websocket: Optional[WebSocket] = None):
        """Handle incoming messages."""
        try:
            recipient_id = message_data.get('recipient')
            message_content = message_data.get('message')
            if not recipient_id or not message_content:
                if websocket:
                    await websocket.send_json({
                        'error': 'Invalid message format. Need recipient and message.'
                    })
                return {
                    'error': 'Invalid message format. Need recipient and message.'
                }
            print(f"Received message from {sender_id} to {recipient_id}: {message_content}")
            # Get or establish shared secret
            shared_secret = await self.redis.get_shared_secret(sender_id, recipient_id)
            if not shared_secret:
                try:
                    shared_secret = await self.establish_shared_secret(sender_id, recipient_id)
                except ValueError as e:
                    if websocket:
                        await websocket.send_json({
                            'error': f'Failed to establish secure channel: {str(e)}'
                        })
                    return {
                        'error': f'Failed to establish secure channel: {str(e)}'
                    }

            # Encrypt message
            encrypted_data = encrypt_message(message_content, shared_secret)
            print(f"Encrypted message: {encrypted_data}")

            # Send to recipient if online
            recipient_ws = self.connections.get(recipient_id)
            if recipient_ws and recipient_ws.client_state == WebSocketState.CONNECTED:
                await recipient_ws.send_json({
                    'type': 'message',
                    'recipient': recipient_id,
                    'sender': sender_id,
                    'message': encrypted_data
                })
            else:
                # Store message in Redis
                await self.redis.store_message(sender_id, recipient_id, encrypted_data)

            return {
                'status': 'success'
            }

        except Exception as e:
            if websocket:
                await websocket.send_json({
                    'error': f'Error processing message: {str(e)}'
                })
            return {
                'error': f'Error processing message: {str(e)}'
            }

    async def get_messages(self, client_id: str, peer_id: Optional[str] = None) -> list[dict]:
        """Get and encrypted messages between client and peer."""
        return await self.redis.get_messages(client_id, peer_id)

    async def send_message(self, client_id: str, message: dict):
        """Send an encrypted message to a peer."""
        await self.handle_message(client_id, message)
