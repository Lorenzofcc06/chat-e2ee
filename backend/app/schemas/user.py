from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional
from datetime import datetime

class Papel(str, Enum):
    USUARIO = "Usuario"
    ADMINISTRADOR = "Administrador"

class UsuarioRegistroRequest(BaseModel):
    nome_usuario: str = Field(..., min_length=3, max_length=50)
    senha: str = Field(..., min_length=6, max_length=128)
    chave_publica: str = Field(..., description="Chave pública RSA em formato PEM")
    papel: Optional[Papel] = Papel.USUARIO

class UsuarioLoginRequest(BaseModel):
    nome_usuario: str
    senha: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    nome_usuario: str
    papel: Papel

class UsuarioResponse(BaseModel):
    id: str
    nome_usuario: str
    chave_publica: str
    papel: Papel
    ativo: bool
    criado_em: Optional[datetime] = None

    class Config:
        from_attributes = True

class UsuarioUpdateRequest(BaseModel):
    papel: Optional[Papel] = None
    ativo: Optional[bool] = None

class ChavePublicaResponse(BaseModel):
    id: str
    nome_usuario: str
    chave_publica: str
