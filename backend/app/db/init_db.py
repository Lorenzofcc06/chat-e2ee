from .session import engine, Base, SessionLocal
from ..models.user import Usuario
from ..models.audit import AuditLog
from ..schemas.user import Papel
from ..core.security import hash_senha
from ..core.logger import log_5w
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from sqlalchemy import text
import logging

def sync_schema():
    """Garante que colunas novas existam no banco sem quebrar tabelas existentes."""
    with engine.connect() as conn:
        # Cria tabela audit_logs se não existir
        Base.metadata.create_all(bind=engine)
        
        # Migração idempotente para PostgreSQL
        try:
            conn.execute(text("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS hash_senha VARCHAR(255);"))
            conn.execute(text("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS ativo BOOLEAN DEFAULT TRUE;"))
            conn.execute(text("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP WITH TIME ZONE DEFAULT NOW();"))
            conn.execute(text("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS atualizado_em TIMESTAMP WITH TIME ZONE DEFAULT NOW();"))
            conn.commit()
        except Exception:
            # Em SQLite ou caso já existam as colunas, prossegue
            pass

def init_db():
    """Inicializa as tabelas do banco de dados e cria o Administrador padrão caso não exista."""
    sync_schema()
    
    db = SessionLocal()
    try:
        admin_existente = db.query(Usuario).filter(Usuario.papel == Papel.ADMINISTRADOR.value).first()
        if not admin_existente:
            # Gera par de chaves RSA para o Administrador padrão
            chave_privada = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            chave_publica_pem = chave_privada.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            admin_user = Usuario(
                nome_usuario="admin",
                hash_senha=hash_senha("Admin@123456"),
                chave_publica=chave_publica_pem,
                papel=Papel.ADMINISTRADOR.value,
                ativo=True
            )
            db.add(admin_user)

            # Cria registro inicial de auditoria
            audit_init = AuditLog(
                who="SYSTEM_INIT",
                what="ADMIN_INITIALIZED",
                where="Database Migration",
                why="Primeiro usuário Administrador ('admin') criado com sucesso para governança do sistema."
            )
            db.add(audit_init)
            db.commit()

            log_5w(
                who="SYSTEM_INIT",
                what="ADMIN_INITIALIZED",
                where="localhost -> Database",
                why="Conta 'admin' inicializada com credenciais padrão (Admin@123456). Altere em produção!"
            )
    except Exception as e:
        db.rollback()
        log_5w(
            who="SYSTEM_INIT",
            what="INIT_DB_ERROR",
            where="Database",
            why=str(e),
            level=logging.ERROR
        )
    finally:
        db.close()
