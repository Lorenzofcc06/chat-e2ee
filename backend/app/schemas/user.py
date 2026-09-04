from pydantic import BaseModel
from enum import Enum

class Papel(str, Enum):
    USUARIO = "Usuario"
    ADMIN = "Admin"

class UsuarioRegistroRequest(BaseModel):
    nome_usuario: str
    chave_publica: str
    papel: Papel = Papel.USUARIO

class UsuarioResponse(BaseModel):
    id: str
    nome_usuario: str
    chave_publica: str
    papel: Papel
