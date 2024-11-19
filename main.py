from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from starlette.websockets import WebSocket, WebSocketDisconnect

from redis_client import SecureRedisClient
from services.messages import MessageService

redis: Optional[SecureRedisClient] = None
messages_service: Optional[MessageService] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis
    global messages_service
    # Initialize Redis connection
    redis = SecureRedisClient()
    messages_service = MessageService(redis)

    yield
    # Close Redis connection on shutdown
    await redis.redis.close()


app = FastAPI(lifespan=lifespan)


@app.get("/messages/{client_id}")
async def get_messages(client_id: str, peer: Optional[str] = Query(None)):
    global messages_service

    return await messages_service.get_messages(client_id, peer)


@app.post("/send")
async def send_message(message: dict):
    """Handle sending encrypted messages between clients."""
    global messages_service

    try:
        # Extract required fields
        client_id = message.get('sender')
        if not client_id:
            raise HTTPException(status_code=400, detail="Missing sender ID")

        # Required fields
        if not all([message.get('recipient'), message.get('encrypted'), message.get('iv'), message.get('session_id')]):
            raise HTTPException(status_code=400, detail="Missing required message fields")

        # Handle the encrypted message
        result = await messages_service.handle_message(client_id, message)

        return {"status": "success", "message_id": result.get("message_id", "")}

    except ValueError as e:
        print(e)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/exchange")
async def initialize_connection(body: dict):
    """Initialize secure channel and exchange keys with client."""
    global messages_service

    try:
        # Validate required fields
        client_id = body.get('clientId')
        client_public_key = body.get('publicKey')

        if not client_id or not client_public_key:
            raise HTTPException(status_code=400, detail="Missing client ID or public key")

        # Initialize secure channel and get session details
        session_id, server_public_key = await messages_service.initialize_secure_channel(
            client_id,
            client_public_key
        )

        return {
            "sessionId": session_id,
            "serverPublicKey": server_public_key
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to initialize secure channel")


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
                await messages_service.handle_message(client_id, message, websocket)

        except WebSocketDisconnect:
            pass

    finally:
        # Cleanup on disconnect
        if client_id in messages_service.connections:
            del messages_service.connections[client_id]
