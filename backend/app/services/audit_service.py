from sqlalchemy.orm import Session
from ..models.audit import AuditLog
from ..core.logger import log_5w
from typing import Optional, List
import logging

class AuditService:
    @staticmethod
    def registrar_evento(
        db: Session,
        who: str,
        what: str,
        where: str,
        why: Optional[str] = "N/A",
        level: int = logging.INFO
    ) -> AuditLog:
        """Registra um evento de auditoria tanto no log 5W (JSON/arquivo) quanto no banco de dados."""
        # 1. Log 5W estruturado
        log_5w(who=who, what=what, where=where, why=why, level=level)

        # 2. Persistência no banco de dados para auditoria formal
        audit_entry = AuditLog(
            who=who,
            what=what,
            where=where,
            why=why
        )
        try:
            db.add(audit_entry)
            db.commit()
            db.refresh(audit_entry)
        except Exception as e:
            db.rollback()
            log_5w(who="SYSTEM", what="AUDIT_PERSISTENCE_ERROR", where="database", why=str(e), level=logging.ERROR)

        return audit_entry

    @staticmethod
    def listar_eventos(db: Session, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        """Recupera histórico de eventos de auditoria ordenados do mais recente para o mais antigo."""
        return db.query(AuditLog).order_by(AuditLog.when.desc()).offset(offset).limit(limit).all()
