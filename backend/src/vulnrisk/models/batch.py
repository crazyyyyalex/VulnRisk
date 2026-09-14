from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from enum import Enum

class BatchStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class BatchVulnerability(BaseModel):
    cve_id: str
    asset_criticality: int
    is_internet_facing: bool = False
    framework: str = "enhanced"

class BatchRequest(BaseModel):
    vulnerabilities: List[BatchVulnerability]
    framework: str = "enhanced"

class BatchResult(BaseModel):
    cve_id: str
    risk_score: float
    priority: str
    timeline_days: int
    explanation: str
    components: Dict[str, float]
    status: str = "success"
    error: Optional[str] = None

class BatchResponse(BaseModel):
    batch_id: str
    status: BatchStatus
    total_count: int
    processed_count: int
    success_count: int
    error_count: int
    results: List[BatchResult]
    progress_percentage: float = 0.0

class BatchProgress(BaseModel):
    batch_id: str
    status: BatchStatus
    processed_count: int
    total_count: int
    progress_percentage: float
    estimated_time_remaining: Optional[int] = None 