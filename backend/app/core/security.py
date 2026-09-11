from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import bcrypt
from jose import jwt, JWTError
from .config import settings

def hash_senha(senha: str) -> str:
    """Gera hash seguro da senha com salt automático usando bcrypt nativo."""
    senha_bytes = senha.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    hash_bytes = bcrypt.hashpw(senha_bytes, salt)
    return hash_bytes.decode("utf-8")

def verificar_senha(senha_plana: str, senha_hasheada: str) -> bool:
    """Verifica se a senha plana corresponde ao hash armazenado."""
    try:
        senha_bytes = senha_plana.encode("utf-8")[:72]
        hash_bytes = senha_hasheada.encode("utf-8")
        return bcrypt.checkpw(senha_bytes, hash_bytes)
    except Exception:
        return False

def criar_token_acesso(dados: Dict[str, Any], expira_delta: Optional[timedelta] = None) -> str:
    """Gera token JWT com claims e tempo de expiração."""
    payload = dados.copy()
    if expira_delta:
        expiracao = datetime.now(timezone.utc) + expira_delta
    else:
        expiracao = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    
    payload.update({"exp": expiracao, "iat": datetime.now(timezone.utc)})
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)
    return token

def decodificar_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodifica e valida o token JWT."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError:
        return None
