from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from ...core.security import decodificar_token
from ...core.logger import log_5w
from ...core.config import settings
from ...db.session import SessionLocal
from ...models.user import Usuario
from .manager import manager
import json
import logging

router = APIRouter(tags=["WebSockets E2EE"])

@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(..., description="Token JWT de autenticação")
):
    client_ip = websocket.client.host if websocket.client else "unknown"

    # 1. Validação de Autenticação no Handshake
    payload = decodificar_token(token)
    if not payload or "username" not in payload:
        log_5w(
            who="ANONYMOUS",
            what="WS_HANDSHAKE_REJECTED",
            where=f"{client_ip} -> /ws",
            why="Token JWT inválido ou ausente no handshake do WebSocket",
            level=logging.WARNING
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Token inválido")
        return

    username = payload["username"]

    # 2. Verificação de status do usuário no Banco de Dados
    db = SessionLocal()
    try:
        usuario = db.query(Usuario).filter(Usuario.nome_usuario == username).first()
        if not usuario or not usuario.ativo:
            log_5w(
                who=username,
                what="WS_HANDSHAKE_REJECTED",
                where=f"{client_ip} -> /ws",
                why="Usuário inexistente ou conta desativada",
                level=logging.WARNING
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Conta inativa")
            return
    finally:
        db.close()

    # 3. Conexão aceita e registrada
    await manager.connect(username=username, websocket=websocket, client_ip=client_ip)

    try:
        while True:
            raw_data = await websocket.receive_text()

            # Defesa contra Exaustão de Recursos (DoS): Tamanho de payload
            if len(raw_data.encode("utf-8")) > settings.max_payload_size_bytes:
                log_5w(
                    who=username,
                    what="DOS_PAYLOAD_SIZE_EXCEEDED",
                    where=f"{client_ip} -> /ws",
                    why=f"Tamanho do payload ({len(raw_data)} bytes) excedeu o limite máximo ({settings.max_payload_size_bytes} bytes).",
                    level=logging.WARNING
                )
                await websocket.send_text(json.dumps({
                    "tipo": "ERRO",
                    "mensagem": "Tamanho da mensagem excede o limite máximo permitido (64KB)."
                }))
                continue

            # Defesa contra Exaustão de Recursos (DoS): Rate limiting do WebSocket
            if not manager.check_rate_limit(username, max_per_minute=60):
                log_5w(
                    who=username,
                    what="DOS_WS_RATE_LIMIT_TRIGGERED",
                    where=f"{client_ip} -> /ws",
                    why="Limite de mensagens/min no WebSocket excedido. Mensagem descartada.",
                    level=logging.WARNING
                )
                await websocket.send_text(json.dumps({
                    "tipo": "ERRO",
                    "mensagem": "Muitas mensagens enviadas em pouco tempo. Aguarde alguns segundos."
                }))
                continue

            try:
                dados_mensagem = json.loads(raw_data)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({
                    "tipo": "ERRO",
                    "mensagem": "Formato de payload inválido (JSON esperado)."
                }))
                continue

            # Roteamento Zero-Knowledge do pacote cifrado
            entregue = await manager.route_message(
                sender_username=username,
                payload=dados_mensagem,
                client_ip=client_ip
            )

            # Confirmação de status de entrega para o remetente
            if entregue:
                await websocket.send_text(json.dumps({
                    "tipo": "STATUS_ENTREGA",
                    "status": "ENTREGUE",
                    "destinatario": dados_mensagem.get("id_destinatario")
                }))
            else:
                await websocket.send_text(json.dumps({
                    "tipo": "STATUS_ENTREGA",
                    "status": "OFFLINE",
                    "destinatario": dados_mensagem.get("id_destinatario"),
                    "mensagem": "O destinatário não está conectado no momento."
                }))

    except WebSocketDisconnect:
        manager.disconnect(username=username, client_ip=client_ip)
    except Exception as e:
        log_5w(
            who=username,
            what="WS_EXCEPTION",
            where=f"{client_ip} -> /ws",
            why=f"Erro inesperado no canal WebSocket: {str(e)}",
            level=logging.ERROR
        )
        manager.disconnect(username=username, client_ip=client_ip)
