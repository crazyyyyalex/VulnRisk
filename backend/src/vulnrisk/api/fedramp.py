"""
FedRAMP VDR Standard API Endpoints

Implements FedRAMP Vulnerability Detection and Response Standard API endpoints
with N1-N5 federal impact classification, LEV/IRV assessment, and timeline enforcement.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth.auth0_jwt import get_current_user_optional
from ..frameworks.fedramp_rfc0012 import CISAKEVClient
from ..frameworks.fedramp_vdr_standard import (
    VDRContext, VDRAssessmentResult, VDRAssessmentEngine
)
from ..services.cve_intelligence import NOT_FOUND_DETAIL, fetch_cve_intelligence
from ..services.incident_response import FedRAMPIncidentResponseManager
from ..services.fedramp_timeline import FedRAMPTimelineManager

router = APIRouter(prefix="/api/v1/fedramp", tags=["FedRAMP VDR Standard"])

# Initialize API clients (CVE/EPSS lookups go through cve_intelligence)
cisa_kev_client = CISAKEVClient()

class FedRAMPAssessmentRequest(BaseModel):
    """FedRAMP RFC-0012 compliant risk assessment request"""
    cve_id: str = Field(..., pattern=r'^CVE-\d{4}-\d{4,}$')
    cvss_base_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    detectability_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    prevalence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    asset_criticality: int = Field(5, ge=1, le=10)
    exposure_multiplier: float = Field(1.0, ge=0.1, le=10.0)
    mission_critical: bool = Field(False)
    federal_data_exposure: float = Field(0.0, ge=0.0, le=100.0)

class FedRAMPComplianceReportRequest(BaseModel):
    organization_name: str
    report_period_days: int = Field(30, ge=1, le=365)

class VDRAssessmentRequest(BaseModel):
    """VDR Standard assessment request with federal-specific fields"""
    cve_id: str = Field(..., pattern=r'^CVE-\d{4}-\d{4,}$')
    
    # Authorization level for timeline calculation
    authorization_level: str = Field("moderate", description="FedRAMP authorization level: low, moderate, or high")
    
    # Asset context
    asset_criticality_rating: str = Field("medium", description="Asset criticality level: low, medium, high, mission_critical")
    
    # Federal impact assessment fields
    service_degradation_hours: Optional[float] = Field(0.0, ge=0.0, description="Estimated service degradation in hours")
    federal_data_exposure_percentage: Optional[float] = Field(0.0, ge=0.0, le=100.0, description="Percentage of affected data that is federal")
    estimated_downtime_hours: Optional[float] = Field(0.0, ge=0.0, description="Estimated downtime in hours")
    affected_users_percentage: Optional[float] = Field(0.0, ge=0.0, le=100.0, description="Percentage of users affected")
    
    # System architecture
    internet_reachable: bool = Field(False, description="Is the vulnerability internet-reachable")
    payload_processing_capabilities: List[str] = Field(default_factory=list, description="System capabilities for processing internet-originated payloads")
    
    # Mitigation status
    current_mitigation_level: str = Field("none", description="Current mitigation level: none, partial, full")
    mitigation_effectiveness: float = Field(0.0, ge=0.0, le=1.0, description="Effectiveness of existing mitigations (0-1)")
    compensating_controls: List[str] = Field(default_factory=list, description="Implemented compensating controls")
    
    # Auto-populated fields
    epss: float = Field(0.0, ge=0.0, le=1.0, description="EPSS score (0-1)")
    known_exploited: bool = Field(False, description="Is this vulnerability known to be exploited")
    patch_available: bool = Field(False, description="Is a patch available")
    mission_critical: bool = Field(False, description="Is the affected system mission critical")
    asset_contains_federal_data: bool = Field(False, description="Does the asset contain federal data")
    
    # Context factors per FRR-VDR-10
    mission_criticality: int = Field(5, ge=1, le=10, description="Mission criticality level (1-10)")
    reachability_paths: List[str] = Field(default_factory=list, description="Threat actor reachability paths")
    # exploitation_likelihood: Auto-populated from EPSS score
    vulnerability_discovery_ease: float = Field(0.0, ge=0.0, le=1.0, description="How easily attackers can discover this vulnerability")
    inventory_impact_pct: float = Field(0.0, ge=0.0, le=100.0, description="Percentage of inventory affected")
    granted_privilege_level: str = Field("none", description="Privilege level granted if exploited")
    vulnerability_chaining_indicators: List[str] = Field(default_factory=list, description="Indicators of vulnerability chaining potential")
    threat_intel_tags: List[str] = Field(default_factory=list, description="Threat intelligence tags (KEV, active-campaigns, etc.)")

@router.post("/assess")
async def fedramp_risk_assessment(request: FedRAMPAssessmentRequest):
    """Perform RFC-0012 compliant risk assessment"""
    
    try:
        # Fetch missing data from external APIs. One resolve() call covers both
        # CVSS and EPSS and falls back to the backup provider chain.
        needs_lookup = request.cvss_base_score is None or request.epss_score is None
        resolved = await fetch_cve_intelligence(request.cve_id) if needs_lookup else None

        if request.cvss_base_score is None:
            if resolved is None or resolved.cve_data is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"CVSS data not found for {request.cve_id}. {NOT_FOUND_DETAIL}",
                )
            cvss_score = resolved.cve_data.cvss_score
        else:
            cvss_score = request.cvss_base_score

        if request.epss_score is None:
            if resolved is not None and resolved.epss_data is not None:
                epss_score = resolved.epss_data.epss_score
            else:
                # Use default EPSS score if not available
                epss_score = 0.1
        else:
            epss_score = request.epss_score
        
        # Enhance with threat intelligence if available
        detectability = request.detectability_score or await get_detectability_score(request.cve_id)
        prevalence = request.prevalence_score or await get_prevalence_score(request.cve_id)
        
        # Check CISA KEV status
        known_exploited = await cisa_kev_client.check_kev_status(request.cve_id)
        
        # Check patch availability
        patch_available = await check_patch_availability(request.cve_id)
        patch_date = await get_patch_date(request.cve_id)
        
        # Create vulnerability context
        context = {
            "cve_id": request.cve_id,
            "cvss_base_score": cvss_score,
            "epss_score": epss_score,
            "detectability_score": detectability,
            "prevalence_score": prevalence,
            "asset_criticality": request.asset_criticality,
            "exposure_multiplier": request.exposure_multiplier,
            "mission_critical": request.mission_critical,
            "federal_data_exposure": request.federal_data_exposure,
            "known_exploited": known_exploited,
            "patch_available": patch_available,
            "patch_date": patch_date
        }
        
        # Calculate FedRAMP risk score using RFC-0012 formula
        risk_score = calculate_fedramp_risk_score(context)
        
        # Determine compliance status
        compliance_status = determine_compliance_status(risk_score, context)
        
        # Generate compliance report
        compliance_report = generate_compliance_report(context, risk_score, compliance_status)
        
        return {
            "cve_id": request.cve_id,
            "risk_score": risk_score,
            "compliance_status": compliance_status,
            "compliance_report": compliance_report,
            "context": context
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.getLogger("vulnrisk.fedramp").exception("FedRAMP assessment failed for %s", request.cve_id)
        raise HTTPException(status_code=500, detail="FedRAMP assessment failed")

def calculate_fedramp_risk_score(context: Dict[str, Any]) -> float:
    """Calculate FedRAMP risk score using RFC-0012 formula"""
    
    # Base CVSS score
    cvss_score = context.get("cvss_base_score", 0.0)
    
    # EPSS adjustment
    epss_score = context.get("epss_score", 0.0)
    epss_adjustment = epss_score * 2.0  # Scale EPSS to 0-2 range
    
    # Asset criticality adjustment
    asset_criticality = context.get("asset_criticality", 5)
    criticality_adjustment = (asset_criticality - 5) * 0.2  # Scale to ±1 range
    
    # Exposure multiplier
    exposure_multiplier = context.get("exposure_multiplier", 1.0)
    
    # Mission critical adjustment
    mission_critical = context.get("mission_critical", False)
    mission_adjustment = 1.5 if mission_critical else 1.0
    
    # Federal data exposure adjustment
    federal_data_exposure = context.get("federal_data_exposure", 0.0)
    federal_adjustment = 1.0 + (federal_data_exposure / 100.0) * 0.5  # Up to 50% increase
    
    # Known exploited adjustment
    known_exploited = context.get("known_exploited", False)
    exploited_adjustment = 1.3 if known_exploited else 1.0
    
    # Calculate final risk score
    risk_score = (
        (cvss_score + epss_adjustment + criticality_adjustment) * 
        exposure_multiplier * 
        mission_adjustment * 
        federal_adjustment * 
        exploited_adjustment
    )
    
    # Cap at 10.0
    return min(risk_score, 10.0)

def determine_compliance_status(risk_score: float, context: Dict[str, Any]) -> Dict[str, Any]:
    """Determine FedRAMP compliance status based on risk score and context"""
    
    # Risk level thresholds
    if risk_score >= 8.0:
        risk_level = "HIGH"
        compliance_status = "NON_COMPLIANT"
    elif risk_score >= 6.0:
        risk_level = "MEDIUM"
        compliance_status = "REQUIRES_ATTENTION"
    else:
        risk_level = "LOW"
        compliance_status = "COMPLIANT"
    
    # Additional compliance checks
    requires_patch = context.get("patch_available", False) and risk_score >= 4.0
    requires_incident_response = context.get("known_exploited", False) or risk_score >= 7.0
    requires_federal_notification = context.get("federal_data_exposure", 0.0) > 50.0 and risk_score >= 5.0
    
    return {
        "risk_level": risk_level,
        "compliance_status": compliance_status,
        "requires_patch": requires_patch,
        "requires_incident_response": requires_incident_response,
        "requires_federal_notification": requires_federal_notification,
        "risk_score": risk_score
    }

def generate_compliance_report(context: Dict[str, Any], risk_score: float, compliance_status: Dict[str, Any]) -> Dict[str, Any]:
    """Generate detailed compliance report"""
    
    return {
        "vulnerability_id": context.get("cve_id"),
        "assessment_date": context.get("assessment_date"),
        "risk_score": risk_score,
        "compliance_status": compliance_status,
        "cvss_base_score": context.get("cvss_base_score"),
        "epss_score": context.get("epss_score"),
        "asset_criticality": context.get("asset_criticality"),
        "mission_critical": context.get("mission_critical"),
        "federal_data_exposure": context.get("federal_data_exposure"),
        "known_exploited": context.get("known_exploited"),
        "patch_available": context.get("patch_available"),
        "recommendations": generate_recommendations(risk_score, compliance_status),
        "next_assessment_due": calculate_next_assessment_date(risk_score)
    }

def generate_recommendations(risk_score: float, compliance_status: Dict[str, Any]) -> List[str]:
    """Generate compliance recommendations based on risk score"""
    
    recommendations = []
    
    if risk_score >= 8.0:
        recommendations.extend([
            "Immediate patching required",
            "Incident response team activation",
            "Federal notification may be required",
            "System isolation consideration"
        ])
    elif risk_score >= 6.0:
        recommendations.extend([
            "Priority patching within 30 days",
            "Enhanced monitoring required",
            "Risk assessment review"
        ])
    else:
        recommendations.extend([
            "Standard patching schedule",
            "Regular monitoring",
            "Annual risk assessment"
        ])
    
    if compliance_status.get("requires_federal_notification"):
        recommendations.append("Federal notification required per FedRAMP requirements")
    
    return recommendations

def calculate_next_assessment_date(risk_score: float) -> str:
    """Calculate next assessment due date based on risk score"""
    
    from datetime import datetime, timedelta
    
    if risk_score >= 8.0:
        days = 7  # Weekly for high risk
    elif risk_score >= 6.0:
        days = 30  # Monthly for medium risk
    else:
        days = 90  # Quarterly for low risk
    
    next_date = datetime.utcnow() + timedelta(days=days)
    return next_date.isoformat()

async def get_detectability_score(cve_id: str) -> float:
    """Get detectability score for CVE"""
    # Placeholder implementation
    return 0.5

async def get_prevalence_score(cve_id: str) -> float:
    """Get prevalence score for CVE"""
    # Placeholder implementation
    return 0.3

async def check_patch_availability(cve_id: str) -> bool:
    """Check if patch is available for CVE"""
    # Placeholder implementation
    return True

async def get_patch_date(cve_id: str) -> Optional[str]:
    """Get patch release date for CVE"""
    # Placeholder implementation
    return None

@router.get("/export-report/excel")
async def export_excel_report():
    """Export compliance report to Excel format"""
    return {"message": "Excel export not yet implemented."}

@router.post("/vdr/assess")
async def vdr_assess(request: VDRAssessmentRequest, user: dict = Depends(get_current_user_optional)):
    """Perform VDR Standard assessment with federal compliance"""
    
    try:
        # Walk the configured provider chain (NVD first, Shodan CVEDB as backup)
        resolved = await fetch_cve_intelligence(request.cve_id, user=user)

        if not resolved.found:
            raise HTTPException(
                status_code=404,
                detail=f"Vulnerability data not found for {request.cve_id}. {NOT_FOUND_DETAIL}",
            )

        cve_data = resolved.cve_data
        epss_data = resolved.epss_data
        
        # Auto-populate VDR context with fetched data
        ctx = VDRContext(
            cve_id=request.cve_id,
            # Federal impact fields (user-provided)
            service_degradation_hours=request.service_degradation_hours,
            federal_data_exposure_percentage=request.federal_data_exposure_percentage,
            estimated_downtime_hours=request.estimated_downtime_hours,
            affected_users_percentage=request.affected_users_percentage,
            
            # Auto-populated from APIs
            internet_reachable=request.internet_reachable,
            mitigation_effectiveness=request.mitigation_effectiveness,
            epss=epss_data.epss_score,  # Auto-fetched
            known_exploited=cve_data.cisa_kev,  # Auto-fetched
            patch_available=bool(cve_data.published_date),  # Auto-determined
            mission_critical=request.mission_critical,
            asset_contains_federal_data=request.asset_contains_federal_data,
            
            # Context factors (auto-populated where possible)
            mission_criticality=request.mission_criticality,
            reachability_paths=request.reachability_paths,
            # exploitation_likelihood is derived from EPSS score in the assessment logic
            vulnerability_discovery_ease=request.vulnerability_discovery_ease or (0.8 if cve_data.has_exploit_references else 0.3),  # Auto-determined
            inventory_impact_pct=request.inventory_impact_pct,
            granted_privilege_level=request.granted_privilege_level,
            vulnerability_chaining_indicators=request.vulnerability_chaining_indicators,
            threat_intel_tags=request.threat_intel_tags or (["cisa_kev"] if cve_data.cisa_kev else [])  # Auto-populate KEV
        )
        
        # Perform VDR assessment with authorization level
        vdr_engine = VDRAssessmentEngine(authorization_level=request.authorization_level)
        result = vdr_engine.assess_vulnerability(ctx)
        
        # Initialize incident response manager
        incident_manager = FedRAMPIncidentResponseManager()
        
        # Check if incident response is required
        requires_incident_response = incident_manager.assess_incident_response_requirement(result)
        
        # Create incident if required
        incident = None
        if requires_incident_response:
            incident = incident_manager.create_incident_from_vdr(result)
        
        # Initialize timeline manager for VDR timelines with correct authorization level
        timeline_manager = FedRAMPTimelineManager(authorization_level=request.authorization_level)
        vdr_timeline = timeline_manager.create_vdr_remediation_timeline(result)
        
        # Return VDR-compliant response with incident and timeline data
        return {
            "cve_id": result.cve_id,
            "impact_rating": result.impact_rating,
            "lev": {
                "status": result.lev_decision.likely_exploitable,
                "reasons": result.lev_decision.reasons
            },
            "irv": {
                "status": result.irv_decision.internet_reachable,
                "reasons": result.irv_decision.reasons,
                "payload_contexts": result.irv_decision.payload_triggered_contexts
            },
            "timeline": {
                "category": result.timeline_classification.category,
                "days": result.timeline_classification.remediation_days
            },
            "context_factors": result.context_factors,
            "incident_response_required": result.incident_response_required,
            "compliance_report": result.compliance_report,
            "federal_impact_fields": {
                "service_degradation_hours": ctx.get('service_degradation_hours'),
                "federal_data_exposure_percentage": ctx.get('federal_data_exposure_percentage'),
                "estimated_downtime_hours": ctx.get('estimated_downtime_hours'),
                "affected_users_percentage": ctx.get('affected_users_percentage'),
            },
            "incident_response": {
                "required": requires_incident_response,
                "incident_id": incident.incident_id if incident else None,
                "severity": incident.severity.value if incident else None,
                "federal_notification_required": incident.federal_notification_required if incident else False,
                "escalation_required": incident.escalation_required if incident else False
            },
            "remediation_timeline": {
                "timeline_days": vdr_timeline.timeline_days,
                "status": vdr_timeline.current_status.value,
                "days_remaining": vdr_timeline.days_remaining,
                "escalation_required": vdr_timeline.escalation_required,
                "responsible_team": vdr_timeline.responsible_team,
                "mitigation_actions": vdr_timeline.mitigation_actions
            },
            "authorization_level": request.authorization_level,
            "assessment_timestamp": result.compliance_report.get('assessment_timestamp'),
            "framework_version": "FedRAMP VDR Standard v1.0"
        }
        
    except HTTPException:
        # Re-raise explicit HTTP errors unchanged
        raise
    except Exception:
        logging.getLogger("vulnrisk.vdr").exception("VDR assessment failed for %s", request.cve_id)
        # Align with other frameworks: surface a 500 for internal errors
        raise HTTPException(status_code=500, detail="VDR assessment failed")

@router.get("/vdr/framework-info")
async def get_vdr_framework_info():
    """Get information about FedRAMP VDR Standard framework"""
    
    return {
        "framework_name": "FedRAMP VDR Standard",
        "version": "1.0",
        "description": "Federal Vulnerability Detection and Response Standard with N1-N5 impact classification",
        "compliance_standards": [
            "FRD-ALL-32: N1-N5 Federal Impact Classification",
            "FRD-ALL-33: Impact Level Definitions", 
            "FRD-ALL-34: Federal Data Exposure Thresholds",
            "FRD-ALL-35: User Impact Classifications",
            "FRD-ALL-23: Likely Exploitable Vulnerability (LEV) Engine",
            "FRD-ALL-24: Internet-Reachable Vulnerability (IRV) Assessment",
            "FRR-VDR-10: Context Factor Evaluation",
            "FRR-VDR-RP-05: Machine-Readable Reporting",
            "FRR-VDR-TF-MO-06: Moderate Impact Timeline Requirements",
            "FRR-VDR-TF-HI-06: High Impact Timeline Requirements"
        ],
        "impact_levels": {
            "N5": "Critical - System-wide failure, complete data loss",
            "N4": "High - Major service degradation, significant data exposure", 
            "N3": "Medium - Limited service impact, moderate data exposure",
            "N2": "Low - Minor service impact, limited data exposure",
            "N1": "Minimal - Negligible impact, no data exposure"
        },
        "timeline_categories": {
            "LEV+IRV": "Likely Exploitable + Internet Reachable (Most Critical)",
            "LEV+NIRV": "Likely Exploitable + Not Internet Reachable",
            "NLEV": "Not Likely Exploitable"
        },
        "required_inputs": [
            "cve_id",
            "authorization_level", 
            "asset_criticality_rating",
            "service_degradation_hours",
            "federal_data_exposure_percentage",
            "estimated_downtime_hours", 
            "affected_users_percentage",
            "internet_reachable",
            "payload_processing_capabilities",
            "current_mitigation_level",
            "mitigation_effectiveness",
            "compensating_controls"
        ],
        "auto_populated_fields": [
            "epss_score",
            "known_exploited_status", 
            "patch_availability",
            "vulnerability_discovery_ease",
            "threat_intelligence_tags"
        ]
    }