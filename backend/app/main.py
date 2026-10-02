from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from .core.logger import log, log_5w
from .core.config import settings
from .core.security import decodificar_token
from .db.init_db import init_db
from .api.routes import auth, users, admin
from .api.websockets import router as ws_router
import time
import logging

# Inicializa o banco de dados e cria o Administrador padrão
init_db()

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Backend E2EE para chat seguro com FastAPI, WebSockets, RBAC, logs 5W e Zero-Knowledge Relay."
)

# CORS liberado para clientes locais
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware de Defesa contra DoS (Payload Size) e Auditoria 5W de Requisições HTTP
@app.middleware("http")
async def security_and_logging_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    method = request.method
    start_time = time.time()

    # 1. Defesa contra Exaustão de Recursos (DoS): Limite do tamanho do corpo da requisição
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_payload_size_bytes:
        log_5w(
            who=client_ip,
            what="DOS_PAYLOAD_TOO_LARGE",
            where=f"{client_ip} -> {method} {path}",
            why=f"Content-Length ({content_length} bytes) excedeu o limite máximo ({settings.max_payload_size_bytes} bytes).",
            level=logging.WARNING
        )
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Payload da requisição excede o tamanho máximo permitido (64KB)."}
        )

    # 2. Identificação do usuário pelo token JWT (se fornecido no cabeçalho Authorization)
    who = "ANONYMOUS"
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        payload = decodificar_token(token)
        if payload and "username" in payload:
            who = payload["username"]

    # 3. Execução da requisição
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)

    # 4. Emissão de Log 5W Estruturado
    log_5w(
        who=who,
        what="HTTP_REQUEST",
        where=f"{client_ip} -> {method} {path}",
        why=f"Status: {response.status_code} | Duração: {duration_ms}ms"
    )

    return response

# Inclusão dos Roteadores REST sob o prefixo /api/v1
app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")

# Inclusão do Roteador WebSockets
app.include_router(ws_router.router)

@app.get("/health", tags=["Monitoramento"])
def health_check():
    """Endpoint para verificação da saúde do serviço."""
    return {
        "status": "online",
        "app": settings.app_name,
        "mode": "Zero-Knowledge Relay",
        "e2ee": True
    }
