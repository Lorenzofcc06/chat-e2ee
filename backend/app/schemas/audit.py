from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class AuditLogResponse(BaseModel):
    id: int
    when: datetime
    who: str
    what: str
    where: str
    why: Optional[str] = None

    class Config:
        from_attributes = True
