from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Callable
from ..db.session import get_db
from ..core.security import decodificar_token
from ..core.rate_limiter import check_rate_limit
from ..core.logger import log_5w
from ..models.user import Usuario
from ..schemas.user import Papel
import logging

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

async def rate_limit_dependency(request: Request):
    await check_rate_limit(request, is_login=False)

async def rate_limit_login_dependency(request: Request):
    await check_rate_limit(request, is_login=True)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Usuario:
    """Extrai e valida o token JWT do usuário autenticado."""
    payload = decodificar_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação com dados incompletos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    usuario = db.query(Usuario).filter(Usuario.id == user_id).first()
    if usuario is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário associado ao token não encontrado",
        )
    
    if not usuario.ativo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Conta de usuário desativada por um administrador",
        )
    
    return usuario

def require_role(papel_exigido: Papel) -> Callable:
    """Controle de Acesso Baseado em Papéis (RBAC)."""
    def role_checker(usuario: Usuario = Depends(get_current_user), request: Request = None) -> Usuario:
        if usuario.papel != papel_exigido.value and usuario.papel != Papel.ADMINISTRADOR.value:
            client_ip = request.client.host if request and request.client else "unknown"
            path = request.url.path if request else "unknown"
            log_5w(
                who=usuario.nome_usuario,
                what="UNAUTHORIZED_ACCESS_ATTEMPT",
                where=f"{client_ip} -> {path}",
                why=f"Papel '{usuario.papel}' tentou acessar recurso restrito a '{papel_exigido.value}'",
                level=logging.WARNING
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acesso negado. Requer papel '{papel_exigido.value}'."
            )
        return usuario
    return role_checker
