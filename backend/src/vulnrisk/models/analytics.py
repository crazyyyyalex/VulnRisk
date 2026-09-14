from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

class RiskDistribution(BaseModel):
    """Risk score distribution data."""
    total_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    unknown_count: int
    average_score: float
    median_score: float
    score_ranges: Dict[str, int]

class TrendData(BaseModel):
    """Trend analysis data."""
    date: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    average_risk_score: float

class AssetAnalysis(BaseModel):
    """Asset criticality analysis."""
    criticality_level: int
    count: int
    average_risk_score: float
    internet_facing_count: int
    internal_count: int

class AnalyticsSummary(BaseModel):
    """Comprehensive analytics summary."""
    risk_distribution: RiskDistribution
    asset_analysis: List[AssetAnalysis]
    top_critical_vulnerabilities: List[Dict[str, Any]]
    recent_trends: List[TrendData]
    processing_stats: Dict[str, Any]

class ReportRequest(BaseModel):
    """Report generation request."""
    report_type: str  # "pdf", "excel", "csv"
    filters: Optional[Dict[str, Any]] = None
    include_charts: bool = True
    include_details: bool = True

class ReportResponse(BaseModel):
    """Report generation response."""
    report_id: str
    download_url: str
    file_size: int
    generated_at: datetime 