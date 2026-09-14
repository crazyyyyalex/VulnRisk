from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class AuditEvent(BaseModel):
    timestamp: datetime
    event_type: str
    cve_id: Optional[str] = None
    description: Optional[str] = None
    details: Optional[dict] = None 