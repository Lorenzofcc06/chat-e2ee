from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime, timezone
from ..db.session import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    when = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    who = Column(String(100), index=True, nullable=False)    # Quem realizou a ação
    what = Column(String(100), index=True, nullable=False)   # Qual evento (ex: USER_REGISTER, LOGIN_SUCCESS)
    where = Column(String(255), nullable=False)              # IP, endpoint ou canal
    why = Column(Text, nullable=True)                        # Motivo, status ou mensagem descritiva
