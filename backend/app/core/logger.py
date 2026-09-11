import logging
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

class Structlog5W(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        extra_data: Dict[str, Any] = getattr(record, "structured_data", {})
        
        log_entry = {
            "when": datetime.now(timezone.utc).isoformat(),
            "who": extra_data.get("who", "SYSTEM"),
            "what": extra_data.get("what", record.getMessage()),
            "where": extra_data.get("where", "UNKNOWN"),
            "why": extra_data.get("why", "N/A"),
            "level": record.levelname
        }
        return json.dumps(log_entry, ensure_ascii=False)

def get_logger():
    logger = logging.getLogger("chat_e2ee")
    if not logger.handlers:
        # Formatter 5W
        formatter = Structlog5W()

        # Handler de Console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Handler de Arquivo de Auditoria
        os.makedirs("logs", exist_ok=True)
        file_handler = logging.FileHandler("logs/audit_5w.log", encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        logger.setLevel(logging.INFO)
    return logger

log = get_logger()

def log_5w(who: str, what: str, where: str, why: str = "N/A", level: int = logging.INFO):
    """Helper para emissão padronizada de logs estruturados nos 5W."""
    log.log(
        level,
        what,
        extra={
            "structured_data": {
                "who": who,
                "what": what,
                "where": where,
                "why": why
            }
        }
    )
