"""
FedRAMP Timeline Management

Handles timeline calculations and compliance tracking for FedRAMP VDR Standard.
Implements exact timeline requirements per FRR-VDR-TF-MO-06 and FRR-VDR-TF-HI-06.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from ..frameworks.fedramp_vdr_standard import VDRAssessmentResult

class RemediationStatus(Enum):
    """Remediation status tracking"""
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    OVERDUE = "overdue"
    COMPLETED = "completed"

@dataclass
class RemediationTimeline:
    vulnerability_id: str
    cve_id: str
    discovery_date: datetime
    required_completion_date: datetime
    timeline_days: int
    current_status: RemediationStatus
    days_remaining: int
    escalation_required: bool
    responsible_team: str
    mitigation_actions: List[str]

class FedRAMPTimelineManager:
    """
    Manages FedRAMP-compliant remediation timelines.
    Implements exact timeline requirements per VDR Standard.
    """
    
    def __init__(self, authorization_level: str = "moderate"):
        self.authorization_level = authorization_level.lower()
        self.escalation_thresholds = {
            0.5: 0,  # Same day escalation for 0.5 day timelines
            1: 0,    # Same day escalation for 1 day timelines
            2: 1,    # 1 day escalation threshold for 2 day timelines
            4: 1,    # 1 day escalation threshold for 4 day timelines
            8: 2,    # 2 day escalation threshold for 8 day timelines
            16: 3,   # 3 day escalation threshold for 16 day timelines
            32: 5,   # 5 day escalation threshold for 32 day timelines
            64: 7,   # 7 day escalation threshold for 64 day timelines
            96: 10,  # 10 day escalation threshold for 96 day timelines
            128: 14, # 14 day escalation threshold for 128 day timelines
            160: 21, # 21 day escalation threshold for 160 day timelines
            192: 30  # 30 day escalation threshold for 192 day timelines
        }
    
    def create_vdr_remediation_timeline(self, vdr_result: VDRAssessmentResult, discovery_date: datetime = None) -> RemediationTimeline:
        """Create VDR-compliant remediation timeline from VDR assessment result"""
        
        if discovery_date is None:
            discovery_date = datetime.utcnow()
        
        # Map VDR timeline category to days using actual VDR assessment data
        timeline_days = self._map_vdr_timeline_category_to_days(
            vdr_result.timeline_classification.category, 
            vdr_result.impact_rating
        )
        completion_date = discovery_date + timedelta(days=timeline_days)
        days_remaining = (completion_date - datetime.utcnow()).days
        
        # Determine status
        if days_remaining < 0:
            status = RemediationStatus.OVERDUE
        elif days_remaining <= self.escalation_thresholds.get(timeline_days, 1):
            status = RemediationStatus.AT_RISK
        else:
            status = RemediationStatus.ON_TRACK
            
        # Determine escalation requirements
        escalation_required = status in [RemediationStatus.OVERDUE, RemediationStatus.AT_RISK]
        
        # Assign responsible team based on VDR classification
        responsible_team = self._assign_responsible_team(vdr_result)
        
        # Generate mitigation actions based on VDR classification
        mitigation_actions = self._generate_mitigation_actions(vdr_result)
        
        return RemediationTimeline(
            vulnerability_id=f"VDR-{vdr_result.cve_id}",
            cve_id=vdr_result.cve_id,
            discovery_date=discovery_date,
            required_completion_date=completion_date,
            timeline_days=timeline_days,
            current_status=status,
            days_remaining=max(0, days_remaining),
            escalation_required=escalation_required,
            responsible_team=responsible_team,
            mitigation_actions=mitigation_actions
        )
    
    def _map_vdr_timeline_category_to_days(self, timeline_category: str, impact_rating: str) -> int:
        """Map VDR timeline category to exact FedRAMP timeline days"""
        
        # Use the exact FedRAMP timeline matrices
        timeline_matrices = {
            'low': {
                'N5': {'LEV_IRV': 4, 'LEV_NIRV': 8, 'NLEV': 32},
                'N4': {'LEV_IRV': 8, 'LEV_NIRV': 32, 'NLEV': 64},
                'N3': {'LEV_IRV': 32, 'LEV_NIRV': 64, 'NLEV': 192},
                'N2': {'LEV_IRV': 96, 'LEV_NIRV': 160, 'NLEV': 192},
                'N1': {'LEV_IRV': 192, 'LEV_NIRV': 192, 'NLEV': 192}
            },
            'moderate': {
                'N5': {'LEV_IRV': 2, 'LEV_NIRV': 4, 'NLEV': 16},
                'N4': {'LEV_IRV': 4, 'LEV_NIRV': 8, 'NLEV': 64},
                'N3': {'LEV_IRV': 16, 'LEV_NIRV': 32, 'NLEV': 128},
                'N2': {'LEV_IRV': 48, 'LEV_NIRV': 128, 'NLEV': 192},
                'N1': {'LEV_IRV': 192, 'LEV_NIRV': 192, 'NLEV': 192}
            },
            'high': {
                'N5': {'LEV_IRV': 0.5, 'LEV_NIRV': 1, 'NLEV': 8},
                'N4': {'LEV_IRV': 2, 'LEV_NIRV': 8, 'NLEV': 32},
                'N3': {'LEV_IRV': 8, 'LEV_NIRV': 16, 'NLEV': 64},
                'N2': {'LEV_IRV': 24, 'LEV_NIRV': 96, 'NLEV': 192},
                'N1': {'LEV_IRV': 192, 'LEV_NIRV': 192, 'NLEV': 192}
            }
        }
        
        # Get the appropriate timeline matrix
        auth_level = self.authorization_level
        if auth_level not in timeline_matrices:
            auth_level = 'moderate'  # Default fallback
        
        # Map timeline category to matrix key (fix direction)
        category_mapping = {
            'LEV_IRV': 'LEV_IRV',    # VDR generates LEV_IRV, maps to LEV_IRV
            'LEV_NIRV': 'LEV_NIRV',  # VDR generates LEV_NIRV, maps to LEV_NIRV
            'NLEV': 'NLEV'           # VDR generates NLEV, maps to NLEV
        }
        
        matrix_key = category_mapping.get(timeline_category, 'NLEV')
        
        # Use actual impact rating from VDR assessment
        impact_level = impact_rating
        
        # Get timeline days from matrix
        timeline_days = timeline_matrices[auth_level][impact_level][matrix_key]
        
        # Convert 0.5 days to 12 hours for practical purposes
        if timeline_days == 0.5:
            timeline_days = 1  # Round up to 1 day for practical implementation
        
        return int(timeline_days)
    
    def _assign_responsible_team(self, vdr_result: VDRAssessmentResult) -> str:
        """Assign responsible team based on VDR classification"""
        
        # Critical vulnerabilities go to security team
        if vdr_result.impact_rating in ['N5', 'N4']:
            return "Security Team"
        
        # LEV+IRV vulnerabilities go to security team
        if vdr_result.timeline_classification.category == 'LEV+IRV':
            return "Security Team"
        
        # LEV+NIRV vulnerabilities go to infrastructure team
        if vdr_result.timeline_classification.category == 'LEV+NIRV':
            return "Infrastructure Team"
        
        # NLEV vulnerabilities go to development team
        return "Development Team"
    
    def _generate_mitigation_actions(self, vdr_result: VDRAssessmentResult) -> List[str]:
        """Generate mitigation actions based on VDR classification"""
        
        actions = []
        
        # Base actions for all vulnerabilities
        actions.append("Apply vendor patch if available")
        actions.append("Implement workaround if patch unavailable")
        actions.append("Update security monitoring rules")
        
        # Additional actions for LEV vulnerabilities
        if vdr_result.timeline_classification.category in ['LEV+IRV', 'LEV+NIRV']:
            actions.append("Implement additional network segmentation")
            actions.append("Deploy additional monitoring and detection")
            actions.append("Conduct security assessment")
        
        # Additional actions for IRV vulnerabilities
        if vdr_result.timeline_classification.category == 'LEV+IRV':
            actions.append("Implement web application firewall rules")
            actions.append("Deploy DDoS protection")
            actions.append("Conduct penetration testing")
        
        # Additional actions for high impact ratings
        if vdr_result.impact_rating in ['N5', 'N4']:
            actions.append("Implement emergency response procedures")
            actions.append("Notify senior management")
            actions.append("Conduct post-incident review")
        
        return actions
    
    def update_timeline_status(self, timeline: RemediationTimeline, new_status: RemediationStatus) -> RemediationTimeline:
        """Update timeline status and recalculate days remaining"""
        
        timeline.current_status = new_status
        
        # Recalculate days remaining
        days_remaining = (timeline.required_completion_date - datetime.utcnow()).days
        timeline.days_remaining = max(0, days_remaining)
        
        # Update escalation requirements
        timeline.escalation_required = timeline.current_status in [RemediationStatus.OVERDUE, RemediationStatus.AT_RISK]
        
        return timeline
    
    def get_timeline_summary(self, timeline: RemediationTimeline) -> Dict[str, Any]:
        """Get timeline summary for reporting"""
        
        return {
            "vulnerability_id": timeline.vulnerability_id,
            "cve_id": timeline.cve_id,
            "timeline_days": timeline.timeline_days,
            "current_status": timeline.current_status.value,
            "days_remaining": timeline.days_remaining,
            "escalation_required": timeline.escalation_required,
            "responsible_team": timeline.responsible_team,
            "mitigation_actions_count": len(timeline.mitigation_actions),
            "discovery_date": timeline.discovery_date.isoformat(),
            "required_completion_date": timeline.required_completion_date.isoformat()
        }
    
    def check_timeline_compliance(self, timeline: RemediationTimeline) -> Dict[str, Any]:
        """Check timeline compliance status"""
        
        compliance_status = {
            "compliant": timeline.current_status != RemediationStatus.OVERDUE,
            "at_risk": timeline.current_status == RemediationStatus.AT_RISK,
            "overdue": timeline.current_status == RemediationStatus.OVERDUE,
            "escalation_required": timeline.escalation_required,
            "days_remaining": timeline.days_remaining,
            "compliance_percentage": self._calculate_compliance_percentage(timeline)
        }
        
        return compliance_status
    
    def _calculate_compliance_percentage(self, timeline: RemediationTimeline) -> float:
        """Calculate compliance percentage based on timeline progress"""
        
        total_days = timeline.timeline_days
        days_elapsed = total_days - timeline.days_remaining
        
        if total_days == 0:
            return 100.0
        
        compliance_pct = (days_elapsed / total_days) * 100
        
        # Cap at 100%
        return min(compliance_pct, 100.0)

class FedRAMPComplianceTracker:
    """
    Tracks FedRAMP compliance metrics and reporting.
    Implements FRR-VDR-RP-05 machine-readable reporting requirements.
    """
    
    def __init__(self):
        self.compliance_metrics = {}
        self.reporting_periods = {
            "daily": 1,
            "weekly": 7,
            "monthly": 30,
            "quarterly": 90
        }
    
    def track_vulnerability_timeline(self, timeline: RemediationTimeline) -> None:
        """Track vulnerability timeline for compliance reporting"""
        
        cve_id = timeline.cve_id
        
        if cve_id not in self.compliance_metrics:
            self.compliance_metrics[cve_id] = {
                "timeline": timeline,
                "status_history": [],
                "compliance_events": [],
                "last_updated": datetime.utcnow()
            }
        
        # Update status history
        self.compliance_metrics[cve_id]["status_history"].append({
            "timestamp": datetime.utcnow(),
            "status": timeline.current_status.value,
            "days_remaining": timeline.days_remaining
        })
        
        # Track compliance events
        if timeline.escalation_required:
            self.compliance_metrics[cve_id]["compliance_events"].append({
                "timestamp": datetime.utcnow(),
                "event_type": "escalation_required",
                "details": f"Timeline at risk with {timeline.days_remaining} days remaining"
            })
        
        # Update last updated timestamp
        self.compliance_metrics[cve_id]["last_updated"] = datetime.utcnow()
    
    def generate_compliance_report(self, report_period: str = "monthly") -> Dict[str, Any]:
        """Generate FedRAMP compliance report"""
        
        period_days = self.reporting_periods.get(report_period, 30)
        cutoff_date = datetime.utcnow() - timedelta(days=period_days)
        
        # Filter metrics for reporting period
        recent_metrics = {
            cve_id: data for cve_id, data in self.compliance_metrics.items()
            if data["last_updated"] >= cutoff_date
        }
        
        # Calculate compliance statistics
        total_vulnerabilities = len(recent_metrics)
        compliant_vulnerabilities = sum(
            1 for data in recent_metrics.values()
            if data["timeline"].current_status != RemediationStatus.OVERDUE
        )
        at_risk_vulnerabilities = sum(
            1 for data in recent_metrics.values()
            if data["timeline"].current_status == RemediationStatus.AT_RISK
        )
        overdue_vulnerabilities = sum(
            1 for data in recent_metrics.values()
            if data["timeline"].current_status == RemediationStatus.OVERDUE
        )
        
        # Calculate compliance percentage
        compliance_percentage = (compliant_vulnerabilities / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 100.0
        
        return {
            "report_period": report_period,
            "report_generated": datetime.utcnow().isoformat(),
            "total_vulnerabilities": total_vulnerabilities,
            "compliant_vulnerabilities": compliant_vulnerabilities,
            "at_risk_vulnerabilities": at_risk_vulnerabilities,
            "overdue_vulnerabilities": overdue_vulnerabilities,
            "compliance_percentage": round(compliance_percentage, 2),
            "vulnerability_details": [
                {
                    "cve_id": cve_id,
                    "timeline_days": data["timeline"].timeline_days,
                    "current_status": data["timeline"].current_status.value,
                    "days_remaining": data["timeline"].days_remaining,
                    "escalation_required": data["timeline"].escalation_required,
                    "responsible_team": data["timeline"].responsible_team
                }
                for cve_id, data in recent_metrics.items()
            ]
        }
    
    def get_compliance_dashboard_data(self) -> Dict[str, Any]:
        """Get data for compliance dashboard"""
        
        # Calculate overall compliance metrics
        total_vulnerabilities = len(self.compliance_metrics)
        
        if total_vulnerabilities == 0:
            return {
                "total_vulnerabilities": 0,
                "compliance_percentage": 100.0,
                "status_breakdown": {
                    "on_track": 0,
                    "at_risk": 0,
                    "overdue": 0,
                    "completed": 0
                },
                "escalation_required": 0,
                "average_days_remaining": 0
            }
        
        # Calculate status breakdown
        status_counts = {}
        escalation_count = 0
        total_days_remaining = 0
        
        for data in self.compliance_metrics.values():
            timeline = data["timeline"]
            status = timeline.current_status.value
            status_counts[status] = status_counts.get(status, 0) + 1
            
            if timeline.escalation_required:
                escalation_count += 1
            
            total_days_remaining += timeline.days_remaining
        
        # Calculate compliance percentage
        compliant_count = status_counts.get("on_track", 0) + status_counts.get("completed", 0)
        compliance_percentage = (compliant_count / total_vulnerabilities) * 100
        
        # Calculate average days remaining
        average_days_remaining = total_days_remaining / total_vulnerabilities
        
        return {
            "total_vulnerabilities": total_vulnerabilities,
            "compliance_percentage": round(compliance_percentage, 2),
            "status_breakdown": {
                "on_track": status_counts.get("on_track", 0),
                "at_risk": status_counts.get("at_risk", 0),
                "overdue": status_counts.get("overdue", 0),
                "completed": status_counts.get("completed", 0)
            },
            "escalation_required": escalation_count,
            "average_days_remaining": round(average_days_remaining, 1)
        }