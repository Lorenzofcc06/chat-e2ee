from sqlalchemy import Column, String, Boolean, DateTime
from datetime import datetime, timezone
import uuid
from ..db.session import Base

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    nome_usuario = Column(String(50), unique=True, index=True, nullable=False)
    hash_senha = Column(String(255), nullable=False)
    chave_publica = Column(String(2048), nullable=False)
    papel = Column(String(20), nullable=False, default="Usuario")  # "Usuario" ou "Administrador"
    ativo = Column(Boolean, default=True, nullable=False)
    criado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    atualizado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
