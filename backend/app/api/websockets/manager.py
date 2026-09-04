from typing import Dict
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        # Mapeia user_id para objeto WebSocket
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, message: str, receiver_id: str):
        if receiver_id in self.active_connections:
            await self.active_connections[receiver_id].send_text(message)

manager = ConnectionManager()
