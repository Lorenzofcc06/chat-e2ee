import logging
import json
from datetime import datetime, timezone
from typing import Any, Dict

class Structlog5W(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Extraindo dados extras passados no log
        extra_data: Dict[str, Any] = getattr(record, "structured_data", {})
        
        log_entry = {
            "when": datetime.now(timezone.utc).isoformat(),
            "who": extra_data.get("who", "SYSTEM"),
            "what": extra_data.get("what", record.getMessage()),
            "where": extra_data.get("where", "UNKNOWN"),
            "why": extra_data.get("why", "N/A"),
            "level": record.levelname
        }
        return json.dumps(log_entry)

def get_logger():
    logger = logging.getLogger("chat_e2ee")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(Structlog5W())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

log = get_logger()
