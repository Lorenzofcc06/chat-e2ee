from typing import Dict, List
from fastapi import WebSocket
from datetime import datetime, timezone
import json
import time
from ...core.logger import log_5w
from ...core.config import settings
import logging

class ConnectionManager:
    def __init__(self):
        # Mapeia nome_usuario -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}
        # Histórico de envio para rate limiting no WebSocket (nome_usuario -> list of timestamps)
        self.message_history: Dict[str, List[float]] = {}

    async def connect(self, username: str, websocket: WebSocket, client_ip: str):
        await websocket.accept()
        # Se já existia uma conexão anterior do mesmo usuário, encerra para evitar duplicidade zumbi
        if username in self.active_connections:
            try:
                await self.active_connections[username].close(code=1000, reason="Nova sessão conectada")
            except Exception:
                pass

        self.active_connections[username] = websocket
        self.message_history[username] = []

        log_5w(
            who=username,
            what="WS_CONNECTED",
            where=f"{client_ip} -> /ws",
            why=f"Usuário '{username}' online. Total de conexões ativas: {len(self.active_connections)}"
        )

    def disconnect(self, username: str, client_ip: str):
        if username in self.active_connections:
            del self.active_connections[username]
        if username in self.message_history:
            del self.message_history[username]

        log_5w(
            who=username,
            what="WS_DISCONNECTED",
            where=f"{client_ip} -> /ws",
            why=f"Usuário '{username}' desconectado. Total de conexões ativas: {len(self.active_connections)}"
        )

    def check_rate_limit(self, username: str, max_per_minute: int = 60) -> bool:
        """Verifica se o usuário está floodando o WebSocket (Defesa DoS)."""
        now = time.time()
        timestamps = self.message_history.get(username, [])
        timestamps = [t for t in timestamps if now - t < 60]
        self.message_history[username] = timestamps

        if len(timestamps) >= max_per_minute:
            return False  # Rate limit exceeded

        timestamps.append(now)
        return True

    def get_online_users(self) -> List[str]:
        return list(self.active_connections.keys())

    async def route_message(self, sender_username: str, payload: dict, client_ip: str) -> bool:
        """Roteia o pacote cifrado diretamente para o destinatário (Zero-Knowledge Relay)."""
        receiver_username = payload.get("id_destinatario")
        if not receiver_username:
            log_5w(
                who=sender_username,
                what="WS_ROUTING_ERROR",
                where=client_ip,
                why="Payload sem campo 'id_destinatario'",
                level=logging.WARNING
            )
            return False

        if receiver_username not in self.active_connections:
            log_5w(
                who=sender_username,
                what="E2EE_MESSAGE_UNDELIVERED",
                where=f"{sender_username} -> {receiver_username}",
                why=f"Destinatário '{receiver_username}' não está conectado no momento.",
                level=logging.INFO
            )
            return False

        dest_ws = self.active_connections[receiver_username]
        # Encaminha o envelope cifrado intacto
        await dest_ws.send_text(json.dumps({
            "tipo": "MENSAGEM_RECEBIDA",
            "dados": payload
        }))

        # Auditoria 5W do tráfego cifrado (O servidor NUNCA tem acesso ao texto claro)
        log_5w(
            who=sender_username,
            what="E2EE_MESSAGE_RELAYED",
            where=f"{sender_username} -> {receiver_username} (WebSocket)",
            why="Mensagem cifrada roteada com sucesso para o destinatário (Zero-Knowledge)"
        )
        return True

manager = ConnectionManager()
