from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from starlette.websockets import WebSocket, WebSocketDisconnect

from redis_client import RedisClient
from services.messages import MessageService

redis: Optional[RedisClient] = None
messages_service: Optional[MessageService] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis
    global messages_service
    # Initialize Redis connection
    redis = RedisClient()
    messages_service = MessageService(redis)

    yield
    # Close Redis connection on shutdown
    await redis.redis.close()


app = FastAPI(lifespan=lifespan)


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    global redis
    global messages_service
    try:
        await websocket.accept()

        # Generate and store keypair for new connection
        private_key, public_key = await messages_service.initialize_secure_channel(client_id)

        # Store connection
        messages_service.connections[client_id] = websocket

        # Send connection confirmation with public key
        await websocket.send_json({
            'type': 'connected',
            'client_id': client_id,
            'public_key': public_key
        })

        # Message handling loop
        try:
            while True:
                message = await websocket.receive_json()
                await messages_service.handle_message(websocket, client_id, message)

        except WebSocketDisconnect:
            pass

    finally:
        # Cleanup on disconnect
        if client_id in messages_service.connections:
            del messages_service.connections[client_id]
        await redis.cleanup_client(client_id)
