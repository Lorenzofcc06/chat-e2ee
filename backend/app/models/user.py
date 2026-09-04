from sqlalchemy import Column, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(String, primary_key=True, index=True)
    nome_usuario = Column(String, unique=True, index=True, nullable=False)
    chave_publica = Column(String, nullable=False)
    papel = Column(String, nullable=False, default="Usuario")
