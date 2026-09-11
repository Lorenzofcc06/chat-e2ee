from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from ..core.config import settings
from ..core.logger import log

# Engine SQLAlchemy parametrizada
connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

try:
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        connect_args=connect_args
    )
except Exception as e:
    log.error(f"Erro ao inicializar engine do banco de dados: {e}")
    # Fallback para sqlite local de desenvolvimento caso o postgres não esteja ativo no momento
    engine = create_engine("sqlite:///./chat_e2ee.db", connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Dependency para injeção de sessão do banco de dados em endpoints."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
