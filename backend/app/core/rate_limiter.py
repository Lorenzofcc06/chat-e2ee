import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from .config import settings
from .logger import log_5w
import logging

class InMemoryRateLimiter:
    """Implementação de Rate Limiting por Janela Deslizante (Sliding Window) para mitigação de DoS."""
    def __init__(self):
        # Mapeia identificador (ex: ip) -> lista de timestamps de requisições
        self.requests = defaultdict(list)

    def is_rate_limited(self, key: str, max_requests: int, window_seconds: int = 60) -> bool:
        now = time.time()
        timestamps = self.requests[key]

        # Remove requisições fora da janela de tempo atual
        self.requests[key] = [t for t in timestamps if now - t < window_seconds]

        if len(self.requests[key]) >= max_requests:
            return True

        self.requests[key].append(now)
        return False

limiter = InMemoryRateLimiter()

async def check_rate_limit(request: Request, is_login: bool = False):
    """Verifica e bloqueia requisições que excedam o limite estabelecido (Defesa contra DoS)."""
    client_ip = request.client.host if request.client else "unknown"
    max_requests = settings.rate_limit_login_per_minute if is_login else settings.rate_limit_general_per_minute
    key = f"{client_ip}:{request.url.path}" if is_login else client_ip

    if limiter.is_rate_limited(key, max_requests=max_requests, window_seconds=60):
        log_5w(
            who=client_ip,
            what="DOS_RATE_LIMIT_TRIGGERED",
            where=f"{request.method} {request.url.path}",
            why=f"Limite de {max_requests} req/min atingido. Requisição bloqueada (HTTP 429)",
            level=logging.WARNING
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas requisições enviadas. Limite temporariamente excedido (Proteção contra DoS)."
        )
