"""
FedRAMP Incident Response Management

Handles incident response requirements and creation for FedRAMP VDR Standard compliance.
Implements FRR-VDR-TF-MO-06 and FRR-VDR-TF-HI-06 incident response triggers.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ..frameworks.fedramp_vdr_standard import VDRAssessmentResult

class IncidentSeverity(Enum):
    """Incident severity levels per FedRAMP requirements"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(Enum):
    """Incident status tracking"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"

class IncidentType(Enum):
    """Types of security incidents"""
    VULNERABILITY = "vulnerability"
    BREACH = "breach"
    SECURITY_INCIDENT = "security_incident"

@dataclass
class AuditEvent:
    """Audit trail event for incident tracking"""
    timestamp: datetime
    action: str
    user: str
    details: Dict[str, Any]

@dataclass
class IncidentResponse:
    incident_id: str
    cve_id: str
    incident_type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    assigned_to: Optional[str]
    description: str
    vdr_classification: Dict[str, Any]
    compliance_requirements: List[str]
    escalation_required: bool
    federal_notification_required: bool
    estimated_resolution: Optional[datetime]
    actions_taken: List[str]
    audit_trail: List[AuditEvent]

class FedRAMPIncidentResponseManager:
    """
    Manages incident response for FedRAMP VDR Standard compliance.
    Implements FRR-VDR-TF-MO-06 and FRR-VDR-TF-HI-06 requirements.
    """
    
    def __init__(self):
        self.incident_counter = 0
    
    def assess_incident_response_requirement(self, vdr_result: VDRAssessmentResult) -> bool:
        """Determine if incident response is required based on VDR classification"""
        
        # Incident response required for:
        # 1. N5 or N4 impact ratings with LEV status
        # 2. Any vulnerability requiring federal notification
        # 3. LEV+IRV timeline category (most critical)
        # 4. Vulnerabilities affecting federal data
        
        requires_ir = (
            vdr_result.incident_response_required or
            (vdr_result.impact_rating in ['N5', 'N4'] and vdr_result.lev_decision.likely_exploitable) or
            vdr_result.timeline_classification.category == 'LEV+IRV' or
            vdr_result.context_factors.get('federal_data_exposure_percentage', 0) > 50
        )
        
        return requires_ir
    
    def create_incident_from_vdr(self, vdr_result: VDRAssessmentResult, assigned_to: Optional[str] = None) -> IncidentResponse:
        """Create incident response from VDR assessment result"""
        
        # Determine incident severity based on VDR classification
        severity = self._determine_incident_severity(vdr_result)
        
        # Determine if federal notification is required
        federal_notification_required = self._requires_federal_notification(vdr_result)
        
        # Determine if escalation is required
        escalation_required = self._requires_escalation(vdr_result)
        
        # Create incident description
        description = self._create_incident_description(vdr_result)
        
        # Determine compliance requirements
        compliance_requirements = self._determine_compliance_requirements(vdr_result)
        
        # Create incident ID
        self.incident_counter += 1
        incident_id = f"VDR-{datetime.utcnow().strftime('%Y%m%d')}-{self.incident_counter:04d}"
        
        # Create audit trail
        audit_trail = [
            AuditEvent(
                timestamp=datetime.utcnow(),
                action="incident_created",
                user="vdr_system",
                details={
                    "cve_id": vdr_result.cve_id,
                    "impact_rating": vdr_result.impact_rating,
                    "lev_status": vdr_result.lev_decision.likely_exploitable,
                    "irv_status": vdr_result.irv_decision.internet_reachable
                }
            )
        ]
        
        return IncidentResponse(
            incident_id=incident_id,
            cve_id=vdr_result.cve_id,
            incident_type=IncidentType.VULNERABILITY,
            severity=severity,
            status=IncidentStatus.OPEN,
            created_at=datetime.utcnow(),
            assigned_to=assigned_to,
            description=description,
            vdr_classification={
                "impact_rating": vdr_result.impact_rating,
                "lev_decision": {
                    "likely_exploitable": vdr_result.lev_decision.likely_exploitable,
                    "reasons": vdr_result.lev_decision.reasons
                },
                "irv_decision": {
                    "internet_reachable": vdr_result.irv_decision.internet_reachable,
                    "reasons": vdr_result.irv_decision.reasons
                },
                "timeline_classification": {
                    "category": vdr_result.timeline_classification.category,
                    "remediation_days": vdr_result.timeline_classification.remediation_days
                }
            },
            compliance_requirements=compliance_requirements,
            escalation_required=escalation_required,
            federal_notification_required=federal_notification_required,
            estimated_resolution=self._estimate_resolution_time(vdr_result),
            actions_taken=[],
            audit_trail=audit_trail
        )
    
    def _determine_incident_severity(self, vdr_result: VDRAssessmentResult) -> IncidentSeverity:
        """Determine incident severity based on VDR classification"""
        
        # Critical: N5 with LEV+IRV
        if (vdr_result.impact_rating == 'N5' and 
            vdr_result.lev_decision.likely_exploitable and 
            vdr_result.irv_decision.internet_reachable):
            return IncidentSeverity.CRITICAL
        
        # High: N4 with LEV+IRV or N5 with LEV
        if ((vdr_result.impact_rating == 'N4' and 
             vdr_result.lev_decision.likely_exploitable and 
             vdr_result.irv_decision.internet_reachable) or
            (vdr_result.impact_rating == 'N5' and vdr_result.lev_decision.likely_exploitable)):
            return IncidentSeverity.HIGH
        
        # Medium: N3 with LEV+IRV or N4 with LEV
        if ((vdr_result.impact_rating == 'N3' and 
             vdr_result.lev_decision.likely_exploitable and 
             vdr_result.irv_decision.internet_reachable) or
            (vdr_result.impact_rating == 'N4' and vdr_result.lev_decision.likely_exploitable)):
            return IncidentSeverity.MEDIUM
        
        # Low: All other cases
        return IncidentSeverity.LOW
    
    def _requires_federal_notification(self, vdr_result: VDRAssessmentResult) -> bool:
        """Determine if federal notification is required"""
        
        # Federal notification required for:
        # 1. N5 or N4 impact ratings
        # 2. LEV+IRV vulnerabilities
        # 3. Vulnerabilities affecting federal data
        # 4. Known exploited vulnerabilities
        
        return (
            vdr_result.impact_rating in ['N5', 'N4'] or
            (vdr_result.lev_decision.likely_exploitable and vdr_result.irv_decision.internet_reachable) or
            vdr_result.context_factors.get('federal_data_exposure_percentage', 0) > 50 or
            vdr_result.context_factors.get('known_exploited', False)
        )
    
    def _requires_escalation(self, vdr_result: VDRAssessmentResult) -> bool:
        """Determine if escalation is required"""
        
        # Escalation required for:
        # 1. Critical severity incidents
        # 2. N5 impact ratings
        # 3. LEV+IRV vulnerabilities
        # 4. Federal notification required cases
        
        return (
            vdr_result.impact_rating == 'N5' or
            (vdr_result.lev_decision.likely_exploitable and vdr_result.irv_decision.internet_reachable) or
            self._requires_federal_notification(vdr_result)
        )
    
    def _create_incident_description(self, vdr_result: VDRAssessmentResult) -> str:
        """Create incident description from VDR assessment"""
        
        description_parts = [
            f"VDR Incident for {vdr_result.cve_id}",
            f"Impact Rating: {vdr_result.impact_rating}",
            f"LEV Status: {'Likely Exploitable' if vdr_result.lev_decision.likely_exploitable else 'Not Likely Exploitable'}",
            f"IRV Status: {'Internet Reachable' if vdr_result.irv_decision.internet_reachable else 'Not Internet Reachable'}",
            f"Timeline Category: {vdr_result.timeline_classification.category}",
            f"Remediation Days: {vdr_result.timeline_classification.remediation_days}"
        ]
        
        if vdr_result.lev_decision.reasons:
            description_parts.append(f"LEV Reasons: {', '.join(vdr_result.lev_decision.reasons)}")
        
        if vdr_result.irv_decision.reasons:
            description_parts.append(f"IRV Reasons: {', '.join(vdr_result.irv_decision.reasons)}")
        
        return " | ".join(description_parts)
    
    def _determine_compliance_requirements(self, vdr_result: VDRAssessmentResult) -> List[str]:
        """Determine compliance requirements based on VDR classification"""
        
        requirements = []
        
        # Base VDR requirements
        requirements.append("FRR-VDR-10: Context factor evaluation")
        requirements.append("FRR-VDR-RP-05: Machine-readable reporting")
        
        # Timeline requirements
        if vdr_result.timeline_classification.category == 'LEV+IRV':
            requirements.append("FRR-VDR-TF-HI-06: High impact timeline compliance")
        elif vdr_result.timeline_classification.category == 'LEV+NIRV':
            requirements.append("FRR-VDR-TF-MO-06: Moderate impact timeline compliance")
        
        # Federal notification requirements
        if self._requires_federal_notification(vdr_result):
            requirements.append("FRR-VDR-NF-01: Federal notification required")
        
        # Incident response requirements
        if vdr_result.incident_response_required:
            requirements.append("FRR-VDR-IR-01: Incident response required")
        
        return requirements
    
    def _estimate_resolution_time(self, vdr_result: VDRAssessmentResult) -> datetime:
        """Estimate incident resolution time based on VDR timeline"""
        
        # Use VDR remediation timeline as base
        base_days = vdr_result.timeline_classification.remediation_days
        
        # Add buffer for incident response overhead
        buffer_days = 1 if base_days <= 7 else 3 if base_days <= 30 else 7
        
        return datetime.utcnow() + timedelta(days=base_days + buffer_days)
    
    def update_incident_status(self, incident: IncidentResponse, new_status: IncidentStatus, 
                             action_taken: str, user: str) -> IncidentResponse:
        """Update incident status and add to audit trail"""
        
        # Add action to audit trail
        incident.audit_trail.append(
            AuditEvent(
                timestamp=datetime.utcnow(),
                action="status_update",
                user=user,
                details={
                    "old_status": incident.status.value,
                    "new_status": new_status.value,
                    "action_taken": action_taken
                }
            )
        )
        
        # Update incident
        incident.status = new_status
        incident.actions_taken.append(action_taken)
        
        return incident
    
    def get_incident_summary(self, incident: IncidentResponse) -> Dict[str, Any]:
        """Get incident summary for reporting"""
        
        return {
            "incident_id": incident.incident_id,
            "cve_id": incident.cve_id,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "created_at": incident.created_at.isoformat(),
            "assigned_to": incident.assigned_to,
            "federal_notification_required": incident.federal_notification_required,
            "escalation_required": incident.escalation_required,
            "estimated_resolution": incident.estimated_resolution.isoformat() if incident.estimated_resolution else None,
            "compliance_requirements": incident.compliance_requirements,
            "actions_taken_count": len(incident.actions_taken),
            "audit_events_count": len(incident.audit_trail)
        }