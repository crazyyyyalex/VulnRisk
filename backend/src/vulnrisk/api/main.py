import os
import subprocess
from datetime import datetime
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any
from dotenv import load_dotenv
import json
import uuid
import tempfile
from fastapi.responses import FileResponse

from ..core.risk_calculator import EnhancedContextualFramework, VulnerabilityData, RiskBasedFramework
from ..data_sources.epss import PERCENTILE_TOP_5, PERCENTILE_TOP_10
from ..data_sources.resolver import CVEIntelligenceResolver, configured_source_order
from ..services.cve_intelligence import (
    NOT_FOUND_DETAIL,
    build_cve_intelligence_payload,
    fetch_cve_intelligence,
)
from ..models.batch import BatchRequest, BatchResponse, BatchVulnerability, BatchResult, BatchStatus
from ..services.batch_processor import BatchProcessor
from ..services.analytics import AnalyticsService
# from ..services.enhanced_ai_analytics import enhanced_ai_service
from ..services.scanner_integrations import ScannerIntegrationService, ScannerType
from ..models.analytics import AnalyticsSummary, ReportRequest, ReportResponse
from .fedramp import router as fedramp_router
from .api_keys import router as api_keys_router
from .security_compliance import router as security_compliance_router
from .performance_scalability import router as performance_scalability_router
from ..services.fedramp_timeline import FedRAMPComplianceTracker
from ..models.audit import AuditEvent
import shutil
from ..auth.auth0_jwt import get_current_user, get_current_user_optional
from ..config.feature_flags import feature_flags
from ..utils.feature_guards import require_feature, get_feature_dependency
from ..security.advanced_security import SecurityHeadersMiddleware
from ..models.database import db_manager

load_dotenv()

# Well-analysed CVE used to probe data source availability.
PROBE_CVE_ID = "CVE-2021-44228"

# Intelligent context determination functions using rich NVD/EPSS data
def _has_cvss_vector(cve_data) -> bool:
    """Whether this record actually carries CVSS vector components.

    Backup sources such as Shodan CVEDB publish a base score without the
    vector. Treating their placeholder values as measurements would score
    every fallback CVE as "no impact", so the helpers below fall back to
    the same neutral assumptions they use when no data exists at all.
    """
    return bool(cve_data) and getattr(cve_data, "has_cvss_vector", True)

def _determine_cia_impact_from_cvss(cve_data) -> Dict[str, float]:
    """Determine CIA impact from actual CVSS vector components."""
    if not _has_cvss_vector(cve_data):
        return {"confidentiality": 0.8, "integrity": 0.8, "availability": 0.8}
    
    # Map CVSS impact values to your document's CIA_Impact_Factor scale
    impact_mapping = {
        "HIGH": 1.0,    # Complete system compromise / Total data loss
        "LOW": 0.6,     # Partial compromise / Limited data exposure  
        "NONE": 0.2     # Negligible compromise / No data impact
    }
    
    return {
        "confidentiality": impact_mapping.get(cve_data.confidentiality_impact, 0.8),
        "integrity": impact_mapping.get(cve_data.integrity_impact, 0.8),
        "availability": impact_mapping.get(cve_data.availability_impact, 0.8)
    }

def _determine_attack_complexity_from_cvss(cve_data, is_internet_facing: bool) -> str:
    """Determine attack path complexity from CVSS vector and exposure."""
    if not _has_cvss_vector(cve_data):
        return "direct"
    
    # Use actual CVSS attack vector and complexity
    if cve_data.attack_vector == "NETWORK":
        if is_internet_facing:
            return "direct"  # Network + Internet = direct exploitation
        else:
            return "single-hop"  # Network + Internal = single hop needed
    elif cve_data.attack_vector == "ADJACENT_NETWORK":
        return "multi-hop"  # Adjacent network = multi-hop attack chain
    elif cve_data.attack_vector == "LOCAL":
        return "complex"  # Local = complex attack chain with dependencies
    elif cve_data.attack_vector == "PHYSICAL":
        return "complex"  # Physical = requires insider access
    else:
        return "direct"

def _determine_exploit_availability_from_data(cve_data, epss_data) -> str:
    """Determine exploit availability from CVE references and threat intelligence."""
    if not cve_data:
        return "details"
    
    # Check CISA KEV first (highest priority)
    if cve_data.cisa_kev:
        return "automated"  # KEV = automated tools available (Metasploit modules)
    
    # Check for exploit references in CVE
    if cve_data.has_exploit_references:
        return "manual"  # Public exploit code available
    
    # Use EPSS-based intelligence
    if epss_data and epss_data.epss_score >= 0.5:
        return "poc"  # High EPSS = likely PoC available
    elif epss_data and epss_data.epss_score >= 0.1:
        return "details"  # Medium EPSS = vulnerability details public
    elif epss_data and epss_data.epss_score >= 0.01:
        return "limited"  # Low EPSS = limited details available
    else:
        return "specialized"  # Very low EPSS = specialized knowledge required

def _determine_discovery_difficulty_from_cvss(cve_data, is_internet_facing: bool) -> str:
    """Determine discovery difficulty from CVSS complexity and exposure."""
    if not _has_cvss_vector(cve_data):
        return "standard"
    
    # Internet-facing vulnerabilities are easier to discover
    if is_internet_facing:
        if cve_data.attack_complexity == "LOW":
            return "easy"  # Internet + low complexity = basic tools
        else:
            return "standard"  # Internet + high complexity = standard scanners
    
    # Internal vulnerabilities require more sophisticated discovery
    else:
        if cve_data.privileges_required == "NONE":
            return "authenticated"  # Internal + no privs = authenticated scanning
        elif cve_data.privileges_required == "LOW":
            return "specialized"  # Internal + low privs = specialized techniques
        else:
            return "manual"  # Internal + high privs = manual testing

def _determine_exploitation_frequency_from_intel(cve_data, epss_data) -> str:
    """Determine exploitation frequency from threat intelligence."""
    if not cve_data:
        return "none"
    
    # CISA KEV = confirmed exploitation
    if cve_data.cisa_kev:
        return "kev"  # CISA Known Exploited Vulnerability
    
    # Use EPSS percentile for campaign detection
    if epss_data:
        if epss_data.percentile >= PERCENTILE_TOP_5 and epss_data.epss_score >= 0.8:
            return "active"  # Top 5% + very high score = active campaigns
        elif epss_data.epss_score >= 0.5:
            return "known"  # High score = known exploitation incidents
        elif epss_data.epss_score >= 0.1:
            return "sporadic"  # Medium score = sporadic exploitation
        elif epss_data.epss_score >= 0.01:
            return "none"  # Low score = no known exploitation
        else:
            return "academic"  # Very low = academic interest only
    
    return "none"

def _determine_target_attractiveness_from_criticality(asset_criticality: int) -> str:
    """Map asset criticality to target attractiveness from your document."""
    if asset_criticality >= 9:
        return "high-value"  # Mission critical = financial, healthcare, government
    elif asset_criticality >= 7:
        return "medium-value"  # Important = enterprise, e-commerce
    elif asset_criticality >= 4:
        return "standard"  # Standard business targets
    elif asset_criticality >= 2:
        return "low-value"  # Low-value targets
    else:
        return "specialized"  # Specialized/niche targets

def _determine_threat_actor_sophistication_from_intel(cve_data, epss_data) -> str:
    """Determine threat actor sophistication from exploitation evidence."""
    if not cve_data:
        return "standard"
    
    # CISA KEV often involves sophisticated actors
    if cve_data.cisa_kev:
        # High-value targets with KEV suggest APT
        if epss_data and epss_data.percentile >= PERCENTILE_TOP_10:
            return "apt"  # Advanced persistent threat groups
        else:
            return "organized"  # Organized cybercriminal groups
    
    # High EPSS suggests organized exploitation
    elif epss_data and epss_data.epss_score >= 0.3:
        return "organized"  # Organized cybercriminal groups
    
    # Exploit references suggest skilled individuals
    elif cve_data.has_exploit_references:
        return "skilled"  # Skilled individual attackers
    
    # Default to standard script kiddie level
    else:
        return "standard"  # Script kiddies / automated attacks

def _determine_resource_level_from_context(cve_data, asset_criticality: int) -> str:
    """Determine threat actor resource level from context."""
    if not cve_data:
        return "standard"
    
    # CISA KEV + high-value assets = well-funded
    if cve_data.cisa_kev and asset_criticality >= 8:
        return "well-funded"  # Well-funded operations
    
    # Either KEV or high-value assets = moderate resources
    elif cve_data.cisa_kev or asset_criticality >= 8:
        return "moderate"  # Moderate resource availability
    
    # Standard resource level for most cases
    else:
        return "standard"  # Standard resource level

def _determine_patch_availability_from_age(vulnerability_age_days: int) -> str:
    """Determine patch availability based on CVE age from your document."""
    if vulnerability_age_days <= 7:
        return "none"  # Very new = likely no patch available
    elif vulnerability_age_days <= 30:
        return "complex"  # Recent = patch available but complex deployment
    elif vulnerability_age_days <= 180:
        return "standard"  # Standard = patch available with standard deployment
    elif vulnerability_age_days <= 730:  # 2 years
        return "deployed"  # Older = patch widely deployed
    else:
        return "mandated"  # Very old = patch mandated by vendors/frameworks

def _determine_disclosure_timeline_from_age(vulnerability_age_days: int) -> str:
    """Determine disclosure timeline based on CVE age from your document."""
    if vulnerability_age_days <= 1:
        return "zero-day"  # Same day = potential zero-day
    elif vulnerability_age_days <= 30:
        return "coordinated"  # Recent = coordinated disclosure in progress
    elif vulnerability_age_days <= 90:
        return "standard"  # Standard public disclosure
    elif vulnerability_age_days <= 365:
        return "responsible"  # Responsible disclosure completed
    else:
        return "full"  # Old = full details publicly available

app = FastAPI(title="VulnRisk API", version="1.0.0")

# Initialize CORS origins
cors_origins = []

# Add local development origins if in development environment
if os.getenv("ENVIRONMENT") == "development":
    cors_origins.extend([
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",  # Vite dev server
    ])

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Include routers
app.include_router(fedramp_router)
app.include_router(api_keys_router)
app.include_router(security_compliance_router)
app.include_router(performance_scalability_router)

class VulnerabilityRequest(BaseModel):
    cve_id: str
    asset_criticality: int
    is_internet_facing: bool = False
    framework: str = "enhanced"
    
    # Optional mitigation controls (only used when framework="mitigation-contextual")
    preventive_controls: Optional[List[str]] = Field(default=[], description="Preventive security controls")
    detective_controls: Optional[List[str]] = Field(default=[], description="Detective security controls")
    response_controls: Optional[List[str]] = Field(default=[], description="Response security controls")

class RiskScoreResponse(BaseModel):
    cve_id: str
    risk_score: float
    priority: str
    timeline_days: int
    explanation: str
    components: Dict[str, float]
    # New transparent fields
    calculation_breakdown: Dict[str, Any]
    confidence_score: float
    data_freshness: Dict[str, str]
    recommendations: List[str]
    audit_trail: Dict[str, Any]
    # CVE Intelligence data for frontend components
    cve_intelligence: Dict[str, Any] = Field(default_factory=dict)

class AITrainingRequest(BaseModel):
    data: List[Dict[str, Any]]

class ScannerRequest(BaseModel):
    scanner_type: str
    target: str
    options: Dict[str, Any] = {}

class MultiScannerRequest(BaseModel):
    targets: List[str]
    scanners: List[str]
    options: Dict[str, Any] = {}

# In-memory mapping for generated reports (report_id -> file path, type)
generated_reports = {}

def log_report_audit_event(user: str, report_type: str, filters: dict):
    # In production, use a persistent audit log
    event = AuditEvent(
        timestamp=datetime.utcnow(),
        event_type="report_generated",
        cve_id=None,
        description=f"{report_type} report generated by {user}",
        details={"filters": filters}
    )
    # Here, you would persist the event
    # For demo, just print
    print(event)

@app.get("/health", tags=["Health"])
def health_check() -> dict:
    """Health check endpoint."""
    return {"status": "ok"}

@app.get("/api/v1/config/features", tags=["Configuration"])
async def get_feature_flags():
    """Get available features for current environment"""
    return feature_flags.get_environment_config()

@app.get("/api/v1/data-sources", tags=["Configuration"])
async def get_data_sources(probe: bool = False):
    """Report the CVE provider chain, and optionally probe each source.

    Use this when scoring reports missing vulnerability data: it shows the
    configured order and, with ``?probe=true``, whether each source currently
    answers a known-good CVE.
    """
    order = configured_source_order()
    payload: Dict[str, Any] = {
        "source_order": order,
        "primary": order[0] if order else None,
        "fallbacks": order[1:],
        "cache_ttl_seconds": int(os.getenv("CVE_CACHE_TTL_SECONDS", 3600)),
        "nvd_api_key_configured": bool(os.getenv("NVD_API_KEY")),
    }

    if probe:
        resolver = CVEIntelligenceResolver(nvd_api_key=os.getenv("NVD_API_KEY"))
        probes = {}
        try:
            for name in order:
                source = resolver._get_source(name)
                if source is None:
                    probes[name] = {"reachable": False, "error": "unknown source"}
                    continue
                try:
                    data = await source.get_rich_cve_data(PROBE_CVE_ID)
                    probes[name] = {
                        "reachable": data is not None,
                        "cvss_score": data.cvss_score if data else None,
                        "has_cvss_vector": data.has_cvss_vector if data else None,
                    }
                except Exception as e:
                    probes[name] = {"reachable": False, "error": str(e)}
        finally:
            await resolver.aclose()
        payload["probe_cve_id"] = PROBE_CVE_ID
        payload["probes"] = probes

    return payload

@app.post("/api/v1/score", response_model=RiskScoreResponse)
async def calculate_risk_score(request: VulnerabilityRequest, user: dict = Depends(get_current_user_optional)):
    """Calculate risk score for a single vulnerability using live CVSS/EPSS data."""
    # Walk the configured provider chain (NVD first, Shodan CVEDB as backup)
    resolved = await fetch_cve_intelligence(request.cve_id, user=user)

    if not resolved.found:
        raise HTTPException(status_code=404, detail=NOT_FOUND_DETAIL)

    cve_data = resolved.cve_data
    epss_data = resolved.epss_data

    cvss_score = cve_data.cvss_score
    epss_score = epss_data.epss_score
    has_exploit = cve_data.has_exploit_references or epss_data.epss_score >= 0.3
    is_kev = cve_data.cisa_kev

    # Create vulnerability data based on framework choice
    if request.framework == "enhanced":
        # Enhanced Contextual: User-specified controls with intelligent context
        vuln_data = VulnerabilityData(
            cve_id=request.cve_id,
            cvss_score=cvss_score,
            asset_criticality=request.asset_criticality,
            epss_score=epss_score,
            is_internet_facing=request.is_internet_facing,
            has_exploit=has_exploit,
            is_kev=is_kev,
            network_exposure="internet-facing" if request.is_internet_facing else "internal",
            cia_impact=_determine_cia_impact_from_cvss(cve_data),
            attack_path_complexity=_determine_attack_complexity_from_cvss(cve_data, request.is_internet_facing),
            exploit_availability=_determine_exploit_availability_from_data(cve_data, epss_data),
            discovery_difficulty=_determine_discovery_difficulty_from_cvss(cve_data, request.is_internet_facing),
            exploitation_frequency=_determine_exploitation_frequency_from_intel(cve_data, epss_data),
            target_attractiveness=_determine_target_attractiveness_from_criticality(request.asset_criticality),
            threat_actor_sophistication=_determine_threat_actor_sophistication_from_intel(cve_data, epss_data),
            resource_level=_determine_resource_level_from_context(cve_data, request.asset_criticality),
            vulnerability_age_days=cve_data.vulnerability_age_days,
            patch_availability=_determine_patch_availability_from_age(cve_data.vulnerability_age_days),
            disclosure_timeline=_determine_disclosure_timeline_from_age(cve_data.vulnerability_age_days),
            preventive_controls=request.preventive_controls or [],  # User-specified or none
            detective_controls=request.detective_controls or [],    # User-specified or none
            response_controls=request.response_controls or []       # User-specified or none
        )
        calculator = EnhancedContextualFramework()
    elif request.framework == "mitigation-contextual":
        # Mitigation Contextual: CVE-aware security controls assessment with intelligent context
        vuln_data = VulnerabilityData(
            cve_id=request.cve_id,
            cvss_score=cvss_score,
            asset_criticality=request.asset_criticality,
            epss_score=epss_score,
            is_internet_facing=request.is_internet_facing,
            has_exploit=has_exploit,
            is_kev=is_kev,
            network_exposure="internet-facing" if request.is_internet_facing else "internal",
            cia_impact=_determine_cia_impact_from_cvss(cve_data),
            attack_path_complexity=_determine_attack_complexity_from_cvss(cve_data, request.is_internet_facing),
            exploit_availability=_determine_exploit_availability_from_data(cve_data, epss_data),
            discovery_difficulty=_determine_discovery_difficulty_from_cvss(cve_data, request.is_internet_facing),
            exploitation_frequency=_determine_exploitation_frequency_from_intel(cve_data, epss_data),
            target_attractiveness=_determine_target_attractiveness_from_criticality(request.asset_criticality),
            threat_actor_sophistication=_determine_threat_actor_sophistication_from_intel(cve_data, epss_data),
            resource_level=_determine_resource_level_from_context(cve_data, request.asset_criticality),
            vulnerability_age_days=cve_data.vulnerability_age_days,
            patch_availability=_determine_patch_availability_from_age(cve_data.vulnerability_age_days),
            disclosure_timeline=_determine_disclosure_timeline_from_age(cve_data.vulnerability_age_days),
            preventive_controls=request.preventive_controls or [],  # User-specified controls
            detective_controls=request.detective_controls or [],    # User-specified controls
            response_controls=request.response_controls or []       # User-specified controls
        )
        calculator = EnhancedContextualFramework()  # Same calculator, different data
    elif request.framework == "risk-based":
        # Risk Based: Complete Master Formula with rich NVD/EPSS data
        vuln_data = VulnerabilityData(
            cve_id=request.cve_id,
            cvss_score=cvss_score,
            asset_criticality=request.asset_criticality,
            epss_score=epss_score,
            is_internet_facing=request.is_internet_facing,
            has_exploit=has_exploit,
            is_kev=is_kev,
            network_exposure="internet-facing" if request.is_internet_facing else "internal",
            cia_impact=_determine_cia_impact_from_cvss(cve_data),
            attack_path_complexity=_determine_attack_complexity_from_cvss(cve_data, request.is_internet_facing),
            exploit_availability=_determine_exploit_availability_from_data(cve_data, epss_data),
            discovery_difficulty=_determine_discovery_difficulty_from_cvss(cve_data, request.is_internet_facing),
            exploitation_frequency=_determine_exploitation_frequency_from_intel(cve_data, epss_data),
            target_attractiveness=_determine_target_attractiveness_from_criticality(request.asset_criticality),
            threat_actor_sophistication=_determine_threat_actor_sophistication_from_intel(cve_data, epss_data),
            resource_level=_determine_resource_level_from_context(cve_data, request.asset_criticality),
            vulnerability_age_days=cve_data.vulnerability_age_days,
            patch_availability=_determine_patch_availability_from_age(cve_data.vulnerability_age_days),
            disclosure_timeline=_determine_disclosure_timeline_from_age(cve_data.vulnerability_age_days),
            preventive_controls=request.preventive_controls or [],
            detective_controls=request.detective_controls or [],
            response_controls=request.response_controls or []
        )
        calculator = RiskBasedFramework()  # Master Formula calculator
    else:
        raise HTTPException(status_code=400, detail=f"Unknown framework: {request.framework}")

    result = calculator.calculate_risk(vuln_data)

    # Create CVE intelligence data for frontend components, including
    # which source answered so the UI can flag fallback data.
    cve_intelligence = build_cve_intelligence_payload(resolved)

    # Save to database only if user is authenticated
    if user:
        assessment_data = {
            'cve_id': request.cve_id,
            'risk_score': result.score,
            'priority': result.priority,
            'timeline_days': result.timeline_days,
            'explanation': result.explanation,
            'components': result.components,
            'asset_criticality': request.asset_criticality,
            'is_internet_facing': request.is_internet_facing,
            'framework': request.framework,
            # Save mitigation controls
            'preventive_controls': request.preventive_controls,
            'detective_controls': request.detective_controls,
            'response_controls': request.response_controls,
            # Save transparent calculation data
            'calculation_breakdown': result.calculation_breakdown,
            'confidence_score': result.confidence_score,
            'recommendations': result.recommendations,
            'audit_trail': result.audit_trail,
            # Save CVE intelligence data
            'cve_intelligence': cve_intelligence
        }

        user_id = user.get("sub")
        db_manager.save_risk_assessment(assessment_data, user_id)

    return RiskScoreResponse(
        cve_id=request.cve_id,
        risk_score=result.score,
        priority=result.priority,
        timeline_days=result.timeline_days,
        explanation=result.explanation,
        components=result.components,
        calculation_breakdown=result.calculation_breakdown,
        confidence_score=result.confidence_score,
        data_freshness=result.data_freshness,
        recommendations=result.recommendations,
        audit_trail=result.audit_trail,
        cve_intelligence=cve_intelligence
    )

@app.post("/api/v1/batch-score", response_model=BatchResponse)
async def process_batch(request: BatchRequest):
    """Process a batch of vulnerabilities."""
    batch_id = str(uuid.uuid4())
    
    # Initialize batch processor
    processor = BatchProcessor()
    
    # Process vulnerabilities
    results = await processor.process_batch(request.vulnerabilities)
    
    # Calculate statistics
    total_count = len(request.vulnerabilities)
    success_count = sum(1 for r in results if r.status == "success")
    error_count = total_count - success_count
    
    return BatchResponse(
        batch_id=batch_id,
        status=BatchStatus.COMPLETED,
        total_count=total_count,
        processed_count=total_count,
        success_count=success_count,
        error_count=error_count,
        results=results,
        progress_percentage=100.0
    )

@app.post("/api/v1/upload-csv")
async def upload_csv(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    """Upload and process a CSV file with vulnerabilities."""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")
    
    try:
        # Lazy import pandas only when needed
        try:
            import pandas as pd  # type: ignore
        except ImportError:
            raise HTTPException(status_code=501, detail="CSV upload not available in serverless build")
        # Read CSV file
        df = pd.read_csv(file.file)
        
        # Validate required columns
        required_columns = ['cve_id', 'asset_criticality']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise HTTPException(
                status_code=400, 
                detail=f"Missing required columns: {missing_columns}"
            )
        
        # Convert to batch vulnerabilities
        vulnerabilities = []
        for _, row in df.iterrows():
            # Handle boolean parsing more robustly
            is_internet_facing = False
            if 'is_internet_facing' in df.columns:
                value = str(row.get('is_internet_facing', False)).strip().lower()
                is_internet_facing = value in ['true', '1', 'yes', 'y']
            
            vuln = BatchVulnerability(
                cve_id=str(row['cve_id']).strip(),
                asset_criticality=int(row['asset_criticality']),
                is_internet_facing=is_internet_facing
            )
            vulnerabilities.append(vuln)
        
        # Process batch with customer context
        customer_id = user.get("sub")
        processor = BatchProcessor(customer_id=customer_id)
        results = await processor.process_batch(vulnerabilities)
        
        return {
            "message": f"Processed {len(vulnerabilities)} vulnerabilities",
            "results": [result.dict() for result in results]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

@app.post("/api/v1/analytics", response_model=AnalyticsSummary)
async def generate_analytics(results: List[BatchResult]):
    """Generate analytics from batch processing results."""
    analytics_service = AnalyticsService()
    return analytics_service.analyze_batch_results(results)

@app.post("/api/v1/reports", response_model=ReportResponse)
async def generate_report(request: ReportRequest, user: dict = Depends(get_current_user)):
    """Generate a custom report from batch results."""
    try:
        # Extract data from request
        data = request.filters.get("data", []) if request.filters else []
        if not data:
            raise HTTPException(status_code=400, detail="No data provided for report generation")
        report_id = str(uuid.uuid4())
        file_path = None
        file_size = 0
        # Generate report based on type
        if request.report_type == "csv":
            csv_content = "CVE ID,Risk Score,Priority,Timeline (days),Status,Explanation\n"
            for item in data:
                csv_content += f"{item['cve_id']},{item['risk_score']},{item['priority']},{item['timeline_days']},{item['status']},\"{item['explanation']}\"\n"
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
                tmp.write(csv_content.encode("utf-8"))
                file_path = tmp.name
                file_size = tmp.tell()
        elif request.report_type == "excel":
            try:
                from openpyxl import Workbook  # type: ignore
            except ImportError:
                raise HTTPException(status_code=501, detail="Excel reports not available in serverless build")
            wb = Workbook()
            ws = wb.active
            ws.title = "FedRAMP Report"
            headers = ["CVE ID", "Risk Score", "Priority", "Timeline (days)", "Status", "Explanation"]
            ws.append(headers)
            for item in data:
                ws.append([
                    item.get("cve_id", ""),
                    item.get("risk_score", 0),
                    item.get("priority", ""),
                    item.get("timeline_days", 0),
                    item.get("status", ""),
                    item.get("explanation", "")
                ])
            with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
                wb.save(tmp.name)
                file_path = tmp.name
                file_size = tmp.tell()
        elif request.report_type == "pdf":
            try:
                from reportlab.lib.pagesizes import letter  # type: ignore
                from reportlab.pdfgen import canvas  # type: ignore
            except ImportError:
                raise HTTPException(status_code=501, detail="PDF reports not available in serverless build")
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                c = canvas.Canvas(tmp.name, pagesize=letter)
                width, height = letter
                c.setFont("Helvetica-Bold", 16)
                c.drawString(30, height - 40, "FedRAMP Compliance Report")
                c.setFont("Helvetica", 10)
                y = height - 70
                headers = ["CVE ID", "Risk Score", "Priority", "Timeline (days)", "Status", "Explanation"]
                c.drawString(30, y, " | ".join(headers))
                y -= 20
                for item in data:
                    row = [
                        str(item.get("cve_id", "")),
                        str(item.get("risk_score", 0)),
                        str(item.get("priority", "")),
                        str(item.get("timeline_days", 0)),
                        str(item.get("status", "")),
                        str(item.get("explanation", ""))
                    ]
                    c.drawString(30, y, " | ".join(row)[:120])
                    y -= 15
                    if y < 40:
                        c.showPage()
                        y = height - 40
                c.save()
                file_path = tmp.name
                file_size = tmp.tell()
        else:
            raise HTTPException(status_code=400, detail="Unsupported report type")
        # Store file path for download endpoint
        generated_reports[report_id] = {"path": file_path, "type": request.report_type}
        # Log audit event
        log_report_audit_event(user.get("sub", "unknown"), request.report_type, request.filters)
        download_url = f"/api/v1/reports/{report_id}/download"
        return ReportResponse(
            report_id=report_id,
            report_type=request.report_type,
            download_url=download_url,
            file_size=file_size,
            generated_at=datetime.utcnow()
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@app.get("/api/v1/reports/{report_id}/download")
async def download_report(report_id: str, user: dict = Depends(get_current_user)):
    # Validate report_id and file existence
    report_info = generated_reports.get(report_id)
    if not report_info or not os.path.exists(report_info["path"]):
        raise HTTPException(status_code=404, detail="Report not found or expired")
    file_path = report_info["path"]
    file_type = report_info["type"]
    # Set content type
    if file_type == "pdf":
        content_type = "application/pdf"
        file_ext = ".pdf"
    elif file_type == "excel":
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        file_ext = ".xlsx"
    elif file_type == "csv":
        content_type = "text/csv"
        file_ext = ".csv"
    else:
        content_type = "application/octet-stream"
        file_ext = ""
    filename = f"fedramp_report_{report_id}{file_ext}"
    # Serve file with secure headers
    response = FileResponse(
        file_path,
        media_type=content_type,
        filename=filename,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )
    # Remove file after serving (best effort)
    try:
        os.remove(file_path)
        del generated_reports[report_id]
    except Exception:
        pass
    return response

@app.get("/api/v1/frameworks")
async def list_frameworks():
    """List available risk frameworks."""
    return {
        "frameworks": [
            {
                "id": "enhanced",
                "name": "Enhanced Contextual",
                "description": "Balances technical severity with business context - specify your actual controls"
            },
            {
                "id": "mitigation-contextual", 
                "name": "Mitigation Contextual",
                "description": "CVE-aware security controls assessment with intelligent control effectiveness"
            },
            {
                "id": "risk-based",
                "name": "Risk Based",
                "description": "Complete Master Formula with all context, threat, and temporal multipliers"
            },
            {
                "id": "fedramp-vdr",
                "name": "FedRAMP VDR Standard",
                "description": "N1-N5 federal impact classification, LEV/IRV assessment, and exact timeline enforcement per VDR Standard"
            }
        ]
    }

@app.get("/api/v1/risk-assessments/history")
async def get_risk_assessment_history(user: dict = Depends(get_current_user), limit: int = 50):
    """Get risk assessment history for the current user"""
    user_id = user.get("sub") if user else None
    assessments = db_manager.get_risk_assessments(user_id, limit)
    return {"assessments": assessments}

@app.post("/api/v1/ai/train-model")
@require_feature("model_training")
async def train_ai_model(request: AITrainingRequest):
    """Train AI model for risk prediction using batch results."""
    try:
        # Log the received data for debugging
        print(f"Received {len(request.data)} batch results for AI training")
        if request.data:
            print(f"First result sample: {request.data[0]}")
        
        # Convert batch results to vulnerability data
        vulnerabilities = []
        for result in request.data:
            if result.get("status") == "success":
                vuln_data = {
                    "cve_id": result.get("cve_id", ""),
                    "risk_score": result.get("risk_score", 0),
                    "cvss_score": result.get("components", {}).get("cvss_score", 0),
                    "epss_score": result.get("components", {}).get("epss_score", 0),
                    "published_date": result.get("components", {}).get("published_date", ""),
                    "has_exploit": result.get("components", {}).get("has_exploit", False),
                    "has_poc": result.get("components", {}).get("has_poc", False),
                    "affected_components": result.get("components", {}).get("affected_components", []),
                    "cwe_ids": result.get("components", {}).get("cwe_ids", []),
                    "affected_vendors": result.get("components", {}).get("affected_vendors", []),
                    "description": result.get("components", {}).get("description", ""),
                    "references": result.get("components", {}).get("references", []),
                    "patch_available": result.get("components", {}).get("patch_available", False),
                    "remote_exploitable": result.get("components", {}).get("remote_exploitable", False),
                    "privilege_escalation": result.get("components", {}).get("privilege_escalation", False),
                    "data_exfiltration": result.get("components", {}).get("data_exfiltration", False),
                    "service_disruption": result.get("components", {}).get("service_disruption", False),
                }
                vulnerabilities.append(vuln_data)
        
        if len(vulnerabilities) < 10:
            raise HTTPException(status_code=400, detail="Insufficient data for training (minimum 10 samples required)")
        
        # Train AI model (lazy import to keep Lambda light)
        try:
            from ..services.ai_analytics import AIAnalyticsService  # type: ignore
        except ImportError:
            raise HTTPException(status_code=501, detail="AI analytics not available in serverless build")
        ai_service = AIAnalyticsService()
        training_result = ai_service.train_risk_predictor(vulnerabilities)
        
        if not training_result["success"]:
            raise HTTPException(status_code=500, detail=training_result["message"])
        
        return {
            "message": "AI model trained successfully",
            "model_metrics": training_result["metrics"],
            "training_samples": len(vulnerabilities)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error training AI model: {str(e)}")

@app.post("/api/v1/ai/predict-trends")
@require_feature("ai_risk_prediction")
async def predict_risk_trends(request: AITrainingRequest):
    """Predict future risk trends using AI models."""
    try:
        # Convert batch results to vulnerability data
        vulnerabilities = []
        for result in request.data:
            if result.get("status") == "success":
                vuln_data = {
                    "cve_id": result.get("cve_id", ""),
                    "risk_score": result.get("risk_score", 0),
                    "cvss_score": result.get("components", {}).get("cvss_score", 0),
                    "epss_score": result.get("components", {}).get("epss_score", 0),
                    "published_date": result.get("components", {}).get("published_date", ""),
                    "has_exploit": result.get("components", {}).get("has_exploit", False),
                    "has_poc": result.get("components", {}).get("has_poc", False),
                    "affected_components": result.get("components", {}).get("affected_components", []),
                    "cwe_ids": result.get("components", {}).get("cwe_ids", []),
                    "affected_vendors": result.get("components", {}).get("affected_vendors", []),
                    "description": result.get("components", {}).get("description", ""),
                    "references": result.get("components", {}).get("references", []),
                    "patch_available": result.get("components", {}).get("patch_available", False),
                    "remote_exploitable": result.get("components", {}).get("remote_exploitable", False),
                    "privilege_escalation": result.get("components", {}).get("privilege_escalation", False),
                    "data_exfiltration": result.get("components", {}).get("data_exfiltration", False),
                    "service_disruption": result.get("components", {}).get("service_disruption", False),
                }
                vulnerabilities.append(vuln_data)
        
        # Load AI service and predict trends (lazy import)
        try:
            from ..services.ai_analytics import AIAnalyticsService  # type: ignore
        except ImportError:
            raise HTTPException(status_code=501, detail="AI analytics not available in serverless build")
        ai_service = AIAnalyticsService()
        ai_service.load_models()  # Load pre-trained models
        
        prediction_result = ai_service.predict_risk_trends(vulnerabilities)
        
        if not prediction_result["success"]:
            raise HTTPException(status_code=500, detail=prediction_result["message"])
        
        return {
            "trends": prediction_result["trends"],
            "predictions": prediction_result["predictions"],
            "analysis_samples": len(vulnerabilities)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error predicting trends: {str(e)}")

@app.post("/api/v1/ai/detect-anomalies")
@require_feature("ai_anomaly_detection")
async def detect_anomalies(request: AITrainingRequest):
    """Detect anomalous vulnerabilities using AI."""
    try:
        # Convert batch results to vulnerability data
        vulnerabilities = []
        for result in request.data:
            if result.get("status") == "success":
                vuln_data = {
                    "cve_id": result.get("cve_id", ""),
                    "risk_score": result.get("risk_score", 0),
                    "cvss_score": result.get("components", {}).get("cvss_score", 0),
                    "epss_score": result.get("components", {}).get("epss_score", 0),
                    "published_date": result.get("components", {}).get("published_date", ""),
                    "has_exploit": result.get("components", {}).get("has_exploit", False),
                    "has_poc": result.get("components", {}).get("has_poc", False),
                    "affected_components": result.get("components", {}).get("affected_components", []),
                    "cwe_ids": result.get("components", {}).get("cwe_ids", []),
                    "affected_vendors": result.get("components", {}).get("affected_vendors", []),
                    "description": result.get("components", {}).get("description", ""),
                    "references": result.get("components", {}).get("references", []),
                    "patch_available": result.get("components", {}).get("patch_available", False),
                    "remote_exploitable": result.get("components", {}).get("remote_exploitable", False),
                    "privilege_escalation": result.get("components", {}).get("privilege_escalation", False),
                    "data_exfiltration": result.get("components", {}).get("data_exfiltration", False),
                    "service_disruption": result.get("components", {}).get("service_disruption", False),
                }
                vulnerabilities.append(vuln_data)
        
        # Detect anomalies (lazy import)
        try:
            from ..services.ai_analytics import AIAnalyticsService  # type: ignore
        except ImportError:
            raise HTTPException(status_code=501, detail="AI analytics not available in serverless build")
        ai_service = AIAnalyticsService()
        anomaly_result = ai_service.detect_anomalies(vulnerabilities)
        
        if not anomaly_result["success"]:
            raise HTTPException(status_code=500, detail=anomaly_result["message"])
        
        return {
            "anomaly_count": anomaly_result["anomaly_count"],
            "anomaly_percentage": anomaly_result["anomaly_percentage"],
            "anomalous_vulnerabilities": anomaly_result["anomalous_vulnerabilities"],
            "total_analyzed": len(vulnerabilities)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error detecting anomalies: {str(e)}")

@app.post("/api/v1/ai/recommendations")
@require_feature("ai_recommendations")
async def generate_ai_recommendations(request: AITrainingRequest):
    """Generate intelligent remediation recommendations using AI."""
    try:
        # Convert batch results to vulnerability data
        vulnerabilities = []
        for result in request.data:
            if result.get("status") == "success":
                vuln_data = {
                    "cve_id": result.get("cve_id", ""),
                    "risk_score": result.get("risk_score", 0),
                    "cvss_score": result.get("components", {}).get("cvss_score", 0),
                    "epss_score": result.get("components", {}).get("epss_score", 0),
                    "published_date": result.get("components", {}).get("published_date", ""),
                    "has_exploit": result.get("components", {}).get("has_exploit", False),
                    "has_poc": result.get("components", {}).get("has_poc", False),
                    "affected_components": result.get("components", {}).get("affected_components", []),
                    "cwe_ids": result.get("components", {}).get("cwe_ids", []),
                    "affected_vendors": result.get("components", {}).get("affected_vendors", []),
                    "description": result.get("components", {}).get("description", ""),
                    "references": result.get("components", {}).get("references", []),
                    "patch_available": result.get("components", {}).get("patch_available", False),
                    "remote_exploitable": result.get("components", {}).get("remote_exploitable", False),
                    "privilege_escalation": result.get("components", {}).get("privilege_escalation", False),
                    "data_exfiltration": result.get("components", {}).get("data_exfiltration", False),
                    "service_disruption": result.get("components", {}).get("service_disruption", False),
                }
                vulnerabilities.append(vuln_data)
        
        # Generate recommendations (lazy import)
        try:
            from ..services.ai_analytics import AIAnalyticsService  # type: ignore
        except ImportError:
            raise HTTPException(status_code=501, detail="AI analytics not available in serverless build")
        ai_service = AIAnalyticsService()
        recommendation_result = ai_service.generate_intelligent_recommendations(vulnerabilities)
        
        if not recommendation_result["success"]:
            raise HTTPException(status_code=500, detail=recommendation_result["message"])
        
        return {
            "recommendations": recommendation_result["recommendations"],
            "summary": recommendation_result["summary"],
            "total_vulnerabilities": len(vulnerabilities)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating recommendations: {str(e)}")

@app.post("/api/v1/ai/comprehensive-analysis")
@require_feature("ai_comprehensive_analysis")
async def comprehensive_ai_analysis(request: AITrainingRequest):
    """Perform comprehensive AI analysis including trends, anomalies, and recommendations."""
    try:
        # Convert batch results to vulnerability data
        vulnerabilities = []
        for result in request.data:
            if result.get("status") == "success":
                vuln_data = {
                    "cve_id": result.get("cve_id", ""),
                    "risk_score": result.get("risk_score", 0),
                    "cvss_score": result.get("components", {}).get("cvss_score", 0),
                    "epss_score": result.get("components", {}).get("epss_score", 0),
                    "published_date": result.get("components", {}).get("published_date", ""),
                    "has_exploit": result.get("components", {}).get("has_exploit", False),
                    "has_poc": result.get("components", {}).get("has_poc", False),
                    "affected_components": result.get("components", {}).get("affected_components", []),
                    "cwe_ids": result.get("components", {}).get("cwe_ids", []),
                    "affected_vendors": result.get("components", {}).get("affected_vendors", []),
                    "description": result.get("components", {}).get("description", ""),
                    "references": result.get("components", {}).get("references", []),
                    "patch_available": result.get("components", {}).get("patch_available", False),
                    "remote_exploitable": result.get("components", {}).get("remote_exploitable", False),
                    "privilege_escalation": result.get("components", {}).get("privilege_escalation", False),
                    "data_exfiltration": result.get("components", {}).get("data_exfiltration", False),
                    "service_disruption": result.get("components", {}).get("service_disruption", False),
                }
                vulnerabilities.append(vuln_data)
        
        if len(vulnerabilities) < 5:
            raise HTTPException(status_code=400, detail="Insufficient data for comprehensive analysis (minimum 5 samples required)")
        
        # Initialize AI service (lazy import)
        try:
            from ..services.ai_analytics import AIAnalyticsService  # type: ignore
        except ImportError:
            raise HTTPException(status_code=501, detail="AI analytics not available in serverless build")
        ai_service = AIAnalyticsService()
        ai_service.load_models()  # Load pre-trained models if available
        
        # Perform all analyses
        results = {}
        
        # Trend analysis
        trend_result = ai_service.predict_risk_trends(vulnerabilities)
        if trend_result["success"]:
            results["trends"] = trend_result["trends"]
            results["predictions"] = trend_result["predictions"]
        
        # Anomaly detection
        anomaly_result = ai_service.detect_anomalies(vulnerabilities)
        if anomaly_result["success"]:
            results["anomalies"] = anomaly_result
        
        # Recommendations
        recommendation_result = ai_service.generate_intelligent_recommendations(vulnerabilities)
        if recommendation_result["success"]:
            results["recommendations"] = recommendation_result
        
        # Generate summary statistics
        risk_scores = [v.get("risk_score", 0) for v in vulnerabilities]
        results["summary"] = {
            "total_vulnerabilities": len(vulnerabilities),
            "average_risk_score": sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            "high_risk_count": len([r for r in risk_scores if r >= 7.0]),
            "medium_risk_count": len([r for r in risk_scores if 4.0 <= r < 7.0]),
            "low_risk_count": len([r for r in risk_scores if r < 4.0]),
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
        
        return results
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error performing comprehensive analysis: {str(e)}")

# Scanner Integration Endpoints
@app.get("/api/v1/scanners")
async def get_available_scanners():
    """Get list of available scanners with their capabilities."""
    scanner_service = ScannerIntegrationService()
    return {"scanners": scanner_service.get_available_scanners()}

@app.post("/api/v1/scanners/scan")
@require_feature("scanner_integrations")
async def run_scanner_scan(request: ScannerRequest):
    """Run a single scanner scan."""
    try:
        scanner_service = ScannerIntegrationService()
        
        # Convert string to ScannerType enum
        try:
            scanner_type = ScannerType(request.scanner_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unsupported scanner type: {request.scanner_type}")
        
        # Run scan
        result = await scanner_service.run_scan(scanner_type, request.target, request.options)
        
        return {
            "scan_id": result.scan_id,
            "scanner_type": result.scanner_type.value,
            "target": result.target,
            "status": result.status,
            "start_time": result.start_time.isoformat(),
            "end_time": result.end_time.isoformat() if result.end_time else None,
            "findings": result.findings,
            "summary": result.summary
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scanner scan failed: {str(e)}")

@app.post("/api/v1/scanners/multi-scan")
@require_feature("multi_scanner")
async def run_multi_scanner_scan(request: MultiScannerRequest):
    """Run multiple scanners on multiple targets."""
    try:
        scanner_service = ScannerIntegrationService()
        
        # Convert string scanner types to ScannerType enums
        scanner_types = []
        for scanner_str in request.scanners:
            try:
                scanner_types.append(ScannerType(scanner_str))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Unsupported scanner type: {scanner_str}")
        
        # Run multi-scanner scan
        results = await scanner_service.run_multi_scanner_scan(request.targets, scanner_types, request.options)
        
        # Process results
        scan_results = []
        for result in results:
            if isinstance(result, Exception):
                scan_results.append({
                    "error": str(result),
                    "status": "failed"
                })
            else:
                scan_results.append({
                    "scan_id": result.scan_id,
                    "scanner_type": result.scanner_type.value,
                    "target": result.target,
                    "status": result.status,
                    "start_time": result.start_time.isoformat(),
                    "end_time": result.end_time.isoformat() if result.end_time else None,
                    "findings": result.findings,
                    "summary": result.summary
                })
        
        return {
            "total_scans": len(scan_results),
            "successful_scans": len([r for r in scan_results if r.get("status") == "completed"]),
            "failed_scans": len([r for r in scan_results if r.get("status") == "failed"]),
            "results": scan_results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Multi-scanner scan failed: {str(e)}")

@app.get("/api/v1/scanners/{scanner_type}/status")
async def get_scanner_status(scanner_type: str):
    """Check if a scanner is available and configured."""
    try:
        scanner_service = ScannerIntegrationService()
        
        try:
            scanner_enum = ScannerType(scanner_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unsupported scanner type: {scanner_type}")
        
        scanner = scanner_service.scanners.get(scanner_enum)
        if not scanner:
            return {"available": False, "error": "Scanner not implemented"}
        
        # Check scanner-specific availability
        if scanner_type == "nuclei":
            # Check if nuclei is installed
            try:
                result = subprocess.run(["nuclei", "-version"], capture_output=True, text=True)
                available = result.returncode == 0
                # Extract version from output like "[INF] Nuclei Engine Version: v3.4.4"
                version = None
                if available and result.stdout:
                    for line in result.stdout.split('\n'):
                        if 'Nuclei Engine Version:' in line:
                            version = line.split('Nuclei Engine Version:')[1].strip()
                            break
                if not version and available:
                    version = "Installed"
            except FileNotFoundError:
                available = False
                version = None
        elif scanner_type == "trivy":
            # Check if trivy is installed
            try:
                result = subprocess.run(["trivy", "--version"], capture_output=True, text=True)
                available = result.returncode == 0
                version = result.stdout.strip() if available else None
            except FileNotFoundError:
                available = False
                version = None
        else:
            # For API-based scanners, check environment variables
            if scanner_type == "nessus":
                available = bool(os.getenv("NESSUS_URL") and os.getenv("NESSUS_ACCESS_KEY"))
            elif scanner_type == "openvas":
                available = bool(os.getenv("OPENVAS_URL") and os.getenv("OPENVAS_USERNAME"))
            elif scanner_type == "zap":
                available = bool(os.getenv("ZAP_URL"))
            elif scanner_type == "sonarqube":
                available = bool(os.getenv("SONARQUBE_URL") and os.getenv("SONARQUBE_TOKEN"))
            else:
                available = False
            version = None
        
        return {
            "scanner_type": scanner_type,
            "available": available,
            "version": version,
            "configured": available
        }
        
    except Exception as e:
        return {"available": False, "error": str(e)}

# Advanced Scanner Features
@app.get("/api/v1/scanners/profiles")
async def get_scan_profiles():
    """Get all scan profiles."""
    # Mock data for now - would be database call in real implementation
    profiles = [
        {
            "id": "1",
            "name": "Web Application Security",
            "description": "Comprehensive web application vulnerability scanning",
            "scanners": ["nuclei", "zap"],
            "targets": ["https://example.com", "https://testphp.vulnweb.com"],
            "options": {"severity": "high", "rate_limit": 150},
            "schedule": "0 2 * * *",
            "enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
            "last_run": "2024-01-19T02:00:00Z"
        },
        {
            "id": "2", 
            "name": "Container Security",
            "description": "Container and infrastructure security scanning",
            "scanners": ["trivy"],
            "targets": ["alpine:latest", "nginx:latest"],
            "options": {"severity": "HIGH,CRITICAL", "ignore_unfixed": True},
            "enabled": True,
            "created_at": "2024-01-16T14:30:00Z",
            "last_run": "2024-01-19T03:00:00Z"
        }
    ]
    return {"profiles": profiles}

@app.post("/api/v1/scanners/profiles")
async def create_scan_profile(profile: dict):
    """Create a new scan profile."""
    # Mock implementation - would save to database
    profile_id = f"profile_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    profile["id"] = profile_id
    profile["created_at"] = datetime.now().isoformat()
    return {"profile": profile, "message": "Profile created successfully"}

@app.get("/api/v1/scanners/history")
async def get_scan_history():
    """Get scan history."""
    # Mock data for now - would be database call in real implementation
    history = [
        {
            "scan_id": "scan_001",
            "profile_name": "Web Application Security",
            "scanners": ["nuclei", "zap"],
            "targets": ["https://example.com"],
            "status": "completed",
            "start_time": "2024-01-19T02:00:00Z",
            "end_time": "2024-01-19T02:15:00Z",
            "findings_count": 5,
            "severity_breakdown": {"critical": 1, "high": 2, "medium": 2, "low": 0}
        },
        {
            "scan_id": "scan_002",
            "profile_name": "Container Security", 
            "scanners": ["trivy"],
            "targets": ["alpine:latest"],
            "status": "completed",
            "start_time": "2024-01-19T03:00:00Z",
            "end_time": "2024-01-19T03:05:00Z",
            "findings_count": 3,
            "severity_breakdown": {"critical": 0, "high": 1, "medium": 2, "low": 0}
        }
    ]
    return {"history": history}

@app.get("/api/v1/scanners/config")
async def get_scanner_config():
    """Get scanner configuration."""
    config = {
        "timeout": 300,
        "default_severity": "high",
        "notifications": {
            "email": True,
            "slack": False,
            "dashboard": True
        },
        "data_retention": 90
    }
    return {"config": config}

@app.post("/api/v1/scanners/config")
async def update_scanner_config(config: dict):
    """Update scanner configuration."""
    # Mock implementation - would save to database
    return {"config": config, "message": "Configuration updated successfully"}

# Enhanced AI Analytics Endpoints
@app.post("/api/v1/ai/enhanced/train-model")
@require_feature("model_training")
async def train_enhanced_model(request: AITrainingRequest, user: dict = Depends(get_current_user)):
    """Train enhanced machine learning model with optimized parameters."""
    try:
        # result = enhanced_ai_service.train_enhanced_model(request.data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Enhanced model training failed: {str(e)}")

@app.post("/api/v1/ai/enhanced/predict-risk")
@require_feature("ai_risk_prediction")
async def predict_enhanced_risk(request: AITrainingRequest, user: dict = Depends(get_current_user)):
    """Predict risk scores using enhanced model."""
    try:
        # result = enhanced_ai_service.predict_enhanced_risk(request.data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Enhanced risk prediction failed: {str(e)}")

@app.get("/api/v1/ai/enhanced/model-performance")
@require_feature("ai_risk_prediction")
async def get_enhanced_model_performance(user: dict = Depends(get_current_user)):
    """Get enhanced model performance metrics."""
    try:
        # result = enhanced_ai_service.get_model_performance()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get model performance: {str(e)}")

@app.post("/api/v1/ai/enhanced/detect-drift")
@require_feature("ai_anomaly_detection")
async def detect_model_drift(request: AITrainingRequest, user: dict = Depends(get_current_user)):
    """Detect model drift using current data."""
    try:
        # result = enhanced_ai_service.detect_model_drift(request.data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model drift detection failed: {str(e)}")

@app.post("/api/v1/ai/enhanced/optimize-hyperparameters")
@require_feature("model_training")
async def optimize_hyperparameters(request: AITrainingRequest, user: dict = Depends(get_current_user)):
    """Optimize hyperparameters using Optuna."""
    try:
        # result = enhanced_ai_service.optimize_hyperparameters(request.data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hyperparameter optimization failed: {str(e)}")

@app.get("/api/v1/ai/enhanced/feature-importance")
@require_feature("ai_risk_prediction")
async def get_feature_importance(user: dict = Depends(get_current_user)):
    """Get feature importance analysis from enhanced model."""
    try:
        # performance = enhanced_ai_service.get_model_performance()
        if not performance["success"]:
            return {"success": False, "message": "No trained model available"}
        
        # Get feature importance from current model
        # model = enhanced_ai_service.model_manager.get_current_model()
        if not model:
            return {"success": False, "message": "Failed to load current model"}
        
        # For XGBoost models, feature importance is available
        if hasattr(model, 'feature_importances_'):
            feature_names = performance.get("features", [])
            importance_scores = model.feature_importances_
            
            feature_importance = dict(zip(feature_names, importance_scores))
            
            # Sort by importance
            sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
            
            return {
                "success": True,
                "feature_importance": dict(sorted_features),
                "top_features": sorted_features[:10],
                "model_version": performance["current_version"]
            }
        else:
            return {"success": False, "message": "Feature importance not available for this model type"}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get feature importance: {str(e)}") 