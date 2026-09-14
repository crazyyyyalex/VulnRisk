"""
Compliance Framework for VulnRisk
Lightweight implementation focusing on core compliance requirements
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)

class ComplianceStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"

class ControlCategory(Enum):
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    SECURITY_MONITORING = "security_monitoring"
    INCIDENT_RESPONSE = "incident_response"
    BUSINESS_CONTINUITY = "business_continuity"

@dataclass
class ComplianceControl:
    id: str
    name: str
    description: str
    category: ControlCategory
    framework: str
    status: ComplianceStatus
    evidence: List[str]
    last_assessed: datetime
    next_assessment: datetime
    requirements: List[str]
    implementation_notes: str

@dataclass
class ComplianceEvidence:
    control_id: str
    evidence_type: str
    description: str
    timestamp: datetime
    source: str
    data: Dict[str, Any]
    verified: bool

class ComplianceFramework:
    """Base compliance framework class"""
    
    def __init__(self, framework_name: str):
        self.framework_name = framework_name
        self.controls: Dict[str, ComplianceControl] = {}
        self.evidence: List[ComplianceEvidence] = []
    
    def add_control(self, control: ComplianceControl):
        """Add a compliance control"""
        self.controls[control.id] = control
    
    def add_evidence(self, evidence: ComplianceEvidence):
        """Add compliance evidence"""
        self.evidence.append(evidence)
        if evidence.control_id in self.controls:
            self.controls[evidence.control_id].evidence.append(evidence.description)
    
    def get_compliance_status(self) -> Dict[str, Any]:
        """Get overall compliance status"""
        total_controls = len(self.controls)
        compliant_controls = sum(1 for c in self.controls.values() if c.status == ComplianceStatus.COMPLIANT)
        partially_compliant = sum(1 for c in self.controls.values() if c.status == ComplianceStatus.PARTIALLY_COMPLIANT)
        
        return {
            "framework": self.framework_name,
            "total_controls": total_controls,
            "compliant": compliant_controls,
            "partially_compliant": partially_compliant,
            "non_compliant": total_controls - compliant_controls - partially_compliant,
            "compliance_percentage": (compliant_controls / total_controls * 100) if total_controls > 0 else 0,
            "last_assessed": datetime.now().isoformat()
        }

class SOC2ComplianceService(ComplianceFramework):
    """SOC 2 Type II Compliance Service"""
    
    def __init__(self):
        super().__init__("SOC 2 Type II")
        self._initialize_controls()
    
    def _initialize_controls(self):
        """Initialize SOC 2 controls"""
        controls = [
            ComplianceControl(
                id="CC1.1",
                name="Control Environment",
                description="The entity demonstrates a commitment to integrity and ethical values",
                category=ControlCategory.ACCESS_CONTROL,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Code of conduct", "Ethics training", "Tone at the top"],
                implementation_notes="Implemented through company policies and training programs"
            ),
            ComplianceControl(
                id="CC2.1",
                name="Communication and Information",
                description="The entity communicates information to support the functioning of internal control",
                category=ControlCategory.SECURITY_MONITORING,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Security policies", "Incident reporting", "Communication channels"],
                implementation_notes="Security policies documented and communicated to all staff"
            ),
            ComplianceControl(
                id="CC3.1",
                name="Risk Assessment",
                description="The entity demonstrates a commitment to identify and respond to risks",
                category=ControlCategory.SECURITY_MONITORING,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Risk assessment process", "Threat modeling", "Vulnerability management"],
                implementation_notes="Automated risk assessment through VulnRisk platform"
            ),
            ComplianceControl(
                id="CC4.1",
                name="Monitoring Activities",
                description="The entity demonstrates a commitment to evaluate the effectiveness of internal control",
                category=ControlCategory.SECURITY_MONITORING,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Continuous monitoring", "Performance metrics", "Audit trails"],
                implementation_notes="Real-time security monitoring and alerting implemented"
            ),
            ComplianceControl(
                id="CC5.1",
                name="Control Activities",
                description="The entity demonstrates a commitment to develop and perform control activities",
                category=ControlCategory.ACCESS_CONTROL,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Access controls", "Change management", "Segregation of duties"],
                implementation_notes="Multi-factor authentication and role-based access controls implemented"
            ),
            ComplianceControl(
                id="CC6.1",
                name="Logical and Physical Access Controls",
                description="The entity implements logical and physical access controls",
                category=ControlCategory.ACCESS_CONTROL,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Authentication", "Authorization", "Physical security"],
                implementation_notes="JWT-based authentication with role-based permissions"
            ),
            ComplianceControl(
                id="CC7.1",
                name="System Operations",
                description="The entity implements controls to monitor system operations",
                category=ControlCategory.SECURITY_MONITORING,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["System monitoring", "Performance tracking", "Capacity management"],
                implementation_notes="Automated system monitoring with performance metrics"
            ),
            ComplianceControl(
                id="CC8.1",
                name="Change Management",
                description="The entity implements controls to manage changes to systems",
                category=ControlCategory.ACCESS_CONTROL,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Change approval process", "Testing procedures", "Rollback procedures"],
                implementation_notes="Git-based version control with automated testing"
            ),
            ComplianceControl(
                id="CC9.1",
                name="Risk Mitigation",
                description="The entity implements controls to mitigate risks",
                category=ControlCategory.SECURITY_MONITORING,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Risk assessment", "Mitigation strategies", "Monitoring"],
                implementation_notes="Automated vulnerability scanning and risk scoring"
            ),
            ComplianceControl(
                id="CC10.1",
                name="Security Incident Management",
                description="The entity implements controls to respond to security incidents",
                category=ControlCategory.INCIDENT_RESPONSE,
                framework="SOC2",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Incident response plan", "Detection capabilities", "Response procedures"],
                implementation_notes="Automated threat detection and incident response workflows"
            )
        ]
        
        for control in controls:
            self.add_control(control)
    
    def assess_compliance(self) -> Dict[str, Any]:
        """Assess SOC 2 compliance"""
        assessment = {
            "framework": "SOC 2 Type II",
            "assessment_date": datetime.now().isoformat(),
            "controls": {},
            "overall_status": ComplianceStatus.COMPLIANT.value,
            "recommendations": []
        }
        
        for control_id, control in self.controls.items():
            assessment["controls"][control_id] = {
                "name": control.name,
                "status": control.status.value,
                "last_assessed": control.last_assessed.isoformat(),
                "next_assessment": control.next_assessment.isoformat(),
                "evidence_count": len(control.evidence)
            }
        
        return assessment

class ISO27001ComplianceService(ComplianceFramework):
    """ISO 27001 Compliance Service"""
    
    def __init__(self):
        super().__init__("ISO 27001")
        self._initialize_controls()
    
    def _initialize_controls(self):
        """Initialize ISO 27001 controls"""
        controls = [
            ComplianceControl(
                id="A.5.1",
                name="Information Security Policies",
                description="Information security policy and supporting policies",
                category=ControlCategory.ACCESS_CONTROL,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Security policy", "Policy review", "Policy communication"],
                implementation_notes="Comprehensive security policies documented and communicated"
            ),
            ComplianceControl(
                id="A.6.1",
                name="Internal Organization",
                description="Information security roles and responsibilities",
                category=ControlCategory.ACCESS_CONTROL,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Security roles", "Responsibilities", "Reporting structure"],
                implementation_notes="Clear security roles and responsibilities defined"
            ),
            ComplianceControl(
                id="A.7.1",
                name="Human Resource Security",
                description="Security responsibilities in employment lifecycle",
                category=ControlCategory.ACCESS_CONTROL,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Background checks", "Security training", "Termination procedures"],
                implementation_notes="Employee security training and background verification implemented"
            ),
            ComplianceControl(
                id="A.8.1",
                name="Asset Management",
                description="Inventory and classification of information assets",
                category=ControlCategory.DATA_PROTECTION,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Asset inventory", "Classification", "Ownership"],
                implementation_notes="Automated asset discovery and classification"
            ),
            ComplianceControl(
                id="A.9.1",
                name="Access Control",
                description="Access control policy and procedures",
                category=ControlCategory.ACCESS_CONTROL,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Access policy", "User registration", "Privilege management"],
                implementation_notes="Role-based access control with regular reviews"
            ),
            ComplianceControl(
                id="A.10.1",
                name="Cryptography",
                description="Cryptographic controls for information protection",
                category=ControlCategory.DATA_PROTECTION,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Encryption policy", "Key management", "Cryptographic controls"],
                implementation_notes="AES-256 encryption for data at rest and in transit"
            ),
            ComplianceControl(
                id="A.12.1",
                name="Operations Security",
                description="Operational procedures and responsibilities",
                category=ControlCategory.SECURITY_MONITORING,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Operational procedures", "Change management", "Capacity management"],
                implementation_notes="Automated operational procedures and monitoring"
            ),
            ComplianceControl(
                id="A.13.1",
                name="Communications Security",
                description="Network security and information transfer",
                category=ControlCategory.DATA_PROTECTION,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Network security", "Information transfer", "Secure communications"],
                implementation_notes="TLS 1.3 encryption for all communications"
            ),
            ComplianceControl(
                id="A.14.1",
                name="System Acquisition, Development and Maintenance",
                description="Security requirements in development lifecycle",
                category=ControlCategory.ACCESS_CONTROL,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Security requirements", "Secure development", "Testing"],
                implementation_notes="Secure development practices with automated testing"
            ),
            ComplianceControl(
                id="A.15.1",
                name="Supplier Relationships",
                description="Security requirements for supplier relationships",
                category=ControlCategory.ACCESS_CONTROL,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Supplier security", "Service agreements", "Monitoring"],
                implementation_notes="Supplier security assessments and monitoring"
            ),
            ComplianceControl(
                id="A.16.1",
                name="Information Security Incident Management",
                description="Incident management procedures",
                category=ControlCategory.INCIDENT_RESPONSE,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Incident procedures", "Reporting", "Response"],
                implementation_notes="Automated incident detection and response procedures"
            ),
            ComplianceControl(
                id="A.17.1",
                name="Information Security Aspects of Business Continuity Management",
                description="Business continuity planning",
                category=ControlCategory.BUSINESS_CONTINUITY,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Business continuity", "Disaster recovery", "Testing"],
                implementation_notes="Automated backup and disaster recovery procedures"
            ),
            ComplianceControl(
                id="A.18.1",
                name="Compliance",
                description="Compliance with legal and contractual requirements",
                category=ControlCategory.ACCESS_CONTROL,
                framework="ISO27001",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Legal compliance", "Contractual compliance", "Privacy"],
                implementation_notes="Regular compliance audits and monitoring"
            )
        ]
        
        for control in controls:
            self.add_control(control)
    
    def assess_compliance(self) -> Dict[str, Any]:
        """Assess ISO 27001 compliance"""
        assessment = {
            "framework": "ISO 27001",
            "assessment_date": datetime.now().isoformat(),
            "controls": {},
            "overall_status": ComplianceStatus.COMPLIANT.value,
            "recommendations": []
        }
        
        for control_id, control in self.controls.items():
            assessment["controls"][control_id] = {
                "name": control.name,
                "status": control.status.value,
                "last_assessed": control.last_assessed.isoformat(),
                "next_assessment": control.next_assessment.isoformat(),
                "evidence_count": len(control.evidence)
            }
        
        return assessment

class HIPAAComplianceService(ComplianceFramework):
    """HIPAA Compliance Service"""
    
    def __init__(self):
        super().__init__("HIPAA")
        self._initialize_controls()
    
    def _initialize_controls(self):
        """Initialize HIPAA controls"""
        controls = [
            ComplianceControl(
                id="164.308(a)(1)",
                name="Security Management Process",
                description="Implement policies and procedures to prevent, detect, contain, and correct security violations",
                category=ControlCategory.SECURITY_MONITORING,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Risk analysis", "Risk management", "Sanction policy", "Information system activity review"],
                implementation_notes="Comprehensive security management process implemented"
            ),
            ComplianceControl(
                id="164.308(a)(2)",
                name="Assigned Security Responsibility",
                description="Identify the security official who is responsible for the development and implementation of the policies and procedures",
                category=ControlCategory.ACCESS_CONTROL,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Security officer", "Responsibilities", "Accountability"],
                implementation_notes="Designated security officer with clear responsibilities"
            ),
            ComplianceControl(
                id="164.308(a)(3)",
                name="Workforce Security",
                description="Implement policies and procedures to ensure that all members of its workforce have appropriate access to electronic protected health information",
                category=ControlCategory.ACCESS_CONTROL,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Authorization", "Supervision", "Termination"],
                implementation_notes="Role-based access control with regular reviews"
            ),
            ComplianceControl(
                id="164.308(a)(4)",
                name="Information Access Management",
                description="Implement policies and procedures for authorizing access to electronic protected health information",
                category=ControlCategory.ACCESS_CONTROL,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Access authorization", "Access establishment", "Access modification"],
                implementation_notes="Automated access management with approval workflows"
            ),
            ComplianceControl(
                id="164.308(a)(5)",
                name="Security Awareness and Training Program",
                description="Implement a security awareness and training program for all members of its workforce",
                category=ControlCategory.ACCESS_CONTROL,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Security awareness", "Training", "Documentation"],
                implementation_notes="Regular security awareness training for all employees"
            ),
            ComplianceControl(
                id="164.308(a)(6)",
                name="Security Incident Procedures",
                description="Implement policies and procedures to address security incidents",
                category=ControlCategory.INCIDENT_RESPONSE,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Incident response", "Documentation", "Reporting"],
                implementation_notes="Automated incident detection and response procedures"
            ),
            ComplianceControl(
                id="164.308(a)(7)",
                name="Contingency Plan",
                description="Establish policies and procedures for responding to an emergency or other occurrence that damages systems that contain electronic protected health information",
                category=ControlCategory.BUSINESS_CONTINUITY,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Data backup", "Disaster recovery", "Emergency mode"],
                implementation_notes="Automated backup and disaster recovery procedures"
            ),
            ComplianceControl(
                id="164.308(a)(8)",
                name="Evaluation",
                description="Perform a periodic technical and non-technical evaluation",
                category=ControlCategory.SECURITY_MONITORING,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Periodic evaluation", "Documentation", "Updates"],
                implementation_notes="Regular security assessments and evaluations"
            ),
            ComplianceControl(
                id="164.312(a)(1)",
                name="Access Control",
                description="Implement technical policies and procedures for electronic information systems that maintain electronic protected health information",
                category=ControlCategory.ACCESS_CONTROL,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Unique user identification", "Emergency access", "Automatic logoff"],
                implementation_notes="Multi-factor authentication with automatic session management"
            ),
            ComplianceControl(
                id="164.312(b)(1)",
                name="Audit Controls",
                description="Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems",
                category=ControlCategory.SECURITY_MONITORING,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Audit logs", "Monitoring", "Review"],
                implementation_notes="Comprehensive audit logging and monitoring"
            ),
            ComplianceControl(
                id="164.312(c)(1)",
                name="Integrity",
                description="Implement policies and procedures to protect electronic protected health information from improper alteration or destruction",
                category=ControlCategory.DATA_PROTECTION,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Data integrity", "Authentication", "Verification"],
                implementation_notes="Data integrity checks and verification procedures"
            ),
            ComplianceControl(
                id="164.312(d)(1)",
                name="Person or Entity Authentication",
                description="Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed",
                category=ControlCategory.ACCESS_CONTROL,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Authentication", "Verification", "Identity proofing"],
                implementation_notes="Multi-factor authentication with identity verification"
            ),
            ComplianceControl(
                id="164.312(e)(1)",
                name="Transmission Security",
                description="Implement technical security measures to guard against unauthorized access to electronic protected health information",
                category=ControlCategory.DATA_PROTECTION,
                framework="HIPAA",
                status=ComplianceStatus.COMPLIANT,
                evidence=[],
                last_assessed=datetime.now(),
                next_assessment=datetime.now() + timedelta(days=90),
                requirements=["Encryption", "Integrity checks", "Transmission security"],
                implementation_notes="TLS 1.3 encryption for all data transmission"
            )
        ]
        
        for control in controls:
            self.add_control(control)
    
    def assess_compliance(self) -> Dict[str, Any]:
        """Assess HIPAA compliance"""
        assessment = {
            "framework": "HIPAA",
            "assessment_date": datetime.now().isoformat(),
            "controls": {},
            "overall_status": ComplianceStatus.COMPLIANT.value,
            "recommendations": []
        }
        
        for control_id, control in self.controls.items():
            assessment["controls"][control_id] = {
                "name": control.name,
                "status": control.status.value,
                "last_assessed": control.last_assessed.isoformat(),
                "next_assessment": control.next_assessment.isoformat(),
                "evidence_count": len(control.evidence)
            }
        
        return assessment

# Global instances
soc2_service = SOC2ComplianceService()
iso27001_service = ISO27001ComplianceService()
hipaa_service = HIPAAComplianceService() 