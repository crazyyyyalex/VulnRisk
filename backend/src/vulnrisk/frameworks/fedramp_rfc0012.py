from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import asyncio
import aiohttp
import json

class PotentialAdverseImpact(Enum):
    VERY_HIGH = "very_high"
    HIGH = "high" 
    MODERATE = "moderate"
    LOW = "low"
    VERY_LOW = "very_low"

class ReachabilityStatus(Enum):
    INTERNET_REACHABLE = "internet_reachable"
    NOT_INTERNET_REACHABLE = "not_internet_reachable"
    UNKNOWN = "unknown"

@dataclass
class FedRAMPVulnerabilityContext:
    cve_id: str
    cvss_base_score: float
    asset_criticality: int  # 1-10 scale
    epss_score: float
    is_internet_reachable: bool
    
    # RFC-0012 Specific Requirements
    detectability_score: float  # 0.0-1.0
    prevalence_score: float     # 0.0-1.0  
    mitigation_effectiveness: float  # 0.0-1.0 (0=no mitigation, 1=fully mitigated)
    
    # Asset Context
    asset_contains_federal_data: bool
    asset_mission_critical: bool
    compensating_controls: List[str]
    
    # Temporal Factors
    patch_available: bool
    patch_availability_date: Optional[datetime]
    known_exploited_vulnerability: bool  # CISA KEV status

@dataclass 
class FedRAMPRiskAssessment:
    vulnerability_context: FedRAMPVulnerabilityContext
    risk_score: float
    is_credibly_exploitable: bool
    potential_adverse_impact: PotentialAdverseImpact
    remediation_timeline_days: int
    priority_level: str
    explanation: str
    compliance_notes: str

class FedRAMPRFC0012Calculator:
    """
    RFC-0012 Compliant Risk Calculator
    
    Implements: "Providers MUST adjust the risk and severity of vulnerabilities 
    using CVSS base scores (if applicable) AND the context of the vulnerability, 
    factoring for at least criticality, reachability, exploitability, 
    detectability, prevalence, and mitigation"
    """
    
    def __init__(self):
        self.framework_name = "FedRAMP RFC-0012"
        self.version = "1.0"
        
        # RFC-0012 Factor Weights (configurable per organization)
        self.weights = {
            'cvss': 0.20,           # Base technical severity
            'criticality': 0.25,    # Asset/mission criticality  
            'exploitability': 0.20, # EPSS-based likelihood
            'detectability': 0.15,  # How easy to detect/exploit
            'prevalence': 0.10,     # Active exploitation campaigns
            'mitigation': 0.10      # Existing controls effectiveness
        }
    
    def calculate_risk(self, context: FedRAMPVulnerabilityContext) -> FedRAMPRiskAssessment:
        """Calculate RFC-0012 compliant risk assessment"""
        
        # Step 1: Calculate base risk components
        base_components = self._calculate_base_components(context)
        
        # Step 2: Apply reachability factors
        reachability_adjusted = self._apply_reachability_factors(base_components, context)
        
        # Step 3: Determine if credibly exploitable
        is_credibly_exploitable = self._determine_credible_exploitability(context, reachability_adjusted)
        
        # Step 4: Calculate potential adverse impact
        adverse_impact = self._calculate_potential_adverse_impact(context, reachability_adjusted)
        
        # Step 5: Determine remediation timeline per RFC-0012
        timeline_days = self._calculate_remediation_timeline(context, adverse_impact, is_credibly_exploitable)
        
        # Step 6: Generate compliance explanation
        explanation = self._generate_compliance_explanation(context, base_components, is_credibly_exploitable)
        
        # Step 7: Priority classification
        priority = self._classify_priority(reachability_adjusted, timeline_days, is_credibly_exploitable)
        
        return FedRAMPRiskAssessment(
            vulnerability_context=context,
            risk_score=reachability_adjusted,
            is_credibly_exploitable=is_credibly_exploitable,
            potential_adverse_impact=adverse_impact,
            remediation_timeline_days=timeline_days,
            priority_level=priority,
            explanation=explanation,
            compliance_notes=self._generate_compliance_notes(context, timeline_days)
        )
    
    def _calculate_base_components(self, context: FedRAMPVulnerabilityContext) -> float:
        """Calculate base risk score using RFC-0012 factors"""
        
        # Normalize CVSS to 0-10 scale
        cvss_component = context.cvss_base_score * self.weights['cvss']
        
        # Asset criticality (1-10 scale)
        criticality_component = context.asset_criticality * self.weights['criticality']
        
        # Exploitability (EPSS * 100 to normalize)
        exploitability_component = (context.epss_score * 100) * self.weights['exploitability']
        
        # Detectability (higher score = easier to detect/exploit)
        detectability_component = (context.detectability_score * 10) * self.weights['detectability']
        
        # Prevalence (active exploitation in the wild)
        prevalence_component = (context.prevalence_score * 10) * self.weights['prevalence']
        
        # Mitigation effectiveness (inverted - less mitigation = higher risk)
        mitigation_component = ((1 - context.mitigation_effectiveness) * 10) * self.weights['mitigation']
        
        base_score = (
            cvss_component + 
            criticality_component + 
            exploitability_component + 
            detectability_component + 
            prevalence_component + 
            mitigation_component
        )
        
        return min(base_score, 10.0)  # Cap at 10.0
    
    def _apply_reachability_factors(self, base_score: float, context: FedRAMPVulnerabilityContext) -> float:
        """Apply RFC-0012 reachability multipliers"""
        
        # RFC-0012: "Prioritizing the discovery, mitigation, and remediation of 
        # vulnerabilities in internet-reachable resources"
        if context.is_internet_reachable:
            reachability_multiplier = 2.0
        else:
            reachability_multiplier = 1.0
            
        # Additional multipliers for federal data
        if context.asset_contains_federal_data:
            reachability_multiplier *= 1.2
            
        # Mission critical systems
        if context.asset_mission_critical:
            reachability_multiplier *= 1.1
            
        return min(base_score * reachability_multiplier, 50.0)  # Theoretical max with multipliers
    
    def _determine_credible_exploitability(self, context: FedRAMPVulnerabilityContext, risk_score: float) -> bool:
        """
        RFC-0012 Definition: "A vulnerability where a likely threat actor with knowledge 
        of the vulnerability would likely be able to gain unauthorized access, cause harm, 
        disrupt operations, or otherwise have an undesired adverse impact; vulnerabilities 
        must be reachable and not fully mitigated to be credibly exploitable."
        """
        
        # Must be reachable
        if not context.is_internet_reachable and not context.asset_contains_federal_data:
            base_reachable = False
        else:
            base_reachable = True
        
        # Must not be fully mitigated
        not_fully_mitigated = context.mitigation_effectiveness < 0.95
        
        # Threat actor likelihood (EPSS + detectability + prevalence)
        threat_likelihood = (context.epss_score + context.detectability_score + context.prevalence_score) / 3
        
        # Known exploitation in the wild
        active_exploitation = context.known_exploited_vulnerability
        
        # Combine factors
        credibly_exploitable = (
            base_reachable and 
            not_fully_mitigated and 
            (threat_likelihood > 0.3 or active_exploitation or risk_score > 15.0)
        )
        
        return credibly_exploitable
    
    def _calculate_potential_adverse_impact(self, context: FedRAMPVulnerabilityContext, risk_score: float) -> PotentialAdverseImpact:
        """Calculate potential adverse impact per RFC-0012 definitions"""
        
        # Base impact from asset criticality and CVSS
        base_impact = (context.asset_criticality + context.cvss_base_score) / 2
        
        # Adjust for federal data and mission criticality
        if context.asset_contains_federal_data:
            base_impact += 2
        if context.asset_mission_critical:
            base_impact += 1
            
        # Map to RFC-0012 impact levels
        if base_impact >= 9:
            return PotentialAdverseImpact.VERY_HIGH
        elif base_impact >= 7:
            return PotentialAdverseImpact.HIGH
        elif base_impact >= 5:
            return PotentialAdverseImpact.MODERATE
        elif base_impact >= 3:
            return PotentialAdverseImpact.LOW
        else:
            return PotentialAdverseImpact.VERY_LOW
    
    def _calculate_remediation_timeline(
        self, 
        context: FedRAMPVulnerabilityContext, 
        impact: PotentialAdverseImpact,
        is_credibly_exploitable: bool
    ) -> int:
        """
        Calculate remediation timeline per RFC-0012 requirements:
        
        - Internet-reachable credibly exploitable: 3 days
        - Not internet-reachable credibly exploitable (High/Moderate impact): 7 days  
        - Not internet-reachable credibly exploitable (Low impact): 21 days
        - All other vulnerabilities: 180 days (6 months)
        """
        
        if not is_credibly_exploitable:
            return 180  # 6 months for non-credibly exploitable
            
        if context.is_internet_reachable:
            return 3  # 3 days for internet-reachable
            
        # Not internet-reachable but credibly exploitable
        if impact in [PotentialAdverseImpact.VERY_HIGH, PotentialAdverseImpact.HIGH, PotentialAdverseImpact.MODERATE]:
            return 7  # 7 days
        elif impact == PotentialAdverseImpact.LOW:
            return 21  # 21 days
        else:
            return 180  # Very low impact = 6 months
    
    def _classify_priority(self, risk_score: float, timeline_days: int, is_credibly_exploitable: bool) -> str:
        """Classify priority level for operational use - FIXED LOGIC"""
        
        # FIXED: Proper priority classification based on risk score and exploitability
        if risk_score >= 8.0 and is_credibly_exploitable:
            return "CRITICAL"
        elif risk_score >= 6.0 and is_credibly_exploitable:
            return "HIGH"
        elif risk_score >= 4.0:
            return "MEDIUM"
        elif risk_score >= 2.0:
            return "LOW"
        else:
            return "INFO"
    
    def _generate_compliance_explanation(
        self, 
        context: FedRAMPVulnerabilityContext, 
        base_components: float,
        is_credibly_exploitable: bool
    ) -> str:
        """Generate RFC-0012 compliant explanation"""
        
        explanation = f"RFC-0012 Compliant Risk Assessment for {context.cve_id}:\n\n"
        
        explanation += f"Base Risk Score: {base_components:.2f}\n"
        explanation += f"• CVSS Base Score: {context.cvss_base_score} (weight: {self.weights['cvss']})\n"
        explanation += f"• Asset Criticality: {context.asset_criticality}/10 (weight: {self.weights['criticality']})\n"
        explanation += f"• Exploitability (EPSS): {context.epss_score:.3f} (weight: {self.weights['exploitability']})\n"
        explanation += f"• Detectability: {context.detectability_score:.2f} (weight: {self.weights['detectability']})\n"
        explanation += f"• Prevalence: {context.prevalence_score:.2f} (weight: {self.weights['prevalence']})\n"
        explanation += f"• Mitigation Effectiveness: {context.mitigation_effectiveness:.2f} (weight: {self.weights['mitigation']})\n\n"
        
        explanation += f"Reachability Assessment:\n"
        explanation += f"• Internet Reachable: {'Yes' if context.is_internet_reachable else 'No'}\n"
        explanation += f"• Contains Federal Data: {'Yes' if context.asset_contains_federal_data else 'No'}\n"
        explanation += f"• Mission Critical: {'Yes' if context.asset_mission_critical else 'No'}\n\n"
        
        explanation += f"Credibly Exploitable: {'Yes' if is_credibly_exploitable else 'No'}\n"
        if is_credibly_exploitable:
            explanation += "• Vulnerability is reachable and not fully mitigated\n"
            explanation += "• Threat actor exploitation is likely based on available intelligence\n"
        
        return explanation
    
    def _generate_compliance_notes(self, context: FedRAMPVulnerabilityContext, timeline_days: int) -> str:
        """Generate compliance-specific notes for auditors"""
        
        notes = f"FedRAMP RFC-0012 Compliance Notes:\n\n"
        
        notes += f"Timeline Basis: {timeline_days} days based on:\n"
        if context.is_internet_reachable and timeline_days <= 3:
            notes += "• FRR-CVM-TM-05: Internet-reachable credibly exploitable vulnerabilities\n"
        elif not context.is_internet_reachable and timeline_days <= 7:
            notes += "• FRR-CVM-TM-07: Not internet-reachable, High/Moderate impact\n"
        elif not context.is_internet_reachable and timeline_days <= 21:
            notes += "• FRR-CVM-TM-08: Not internet-reachable, Low impact\n"
        else:
            notes += "• FRR-CVM-TM-09: All remaining detected vulnerabilities\n"
            
        notes += f"\nRequired Actions:\n"
        notes += f"• Assessment completed per FRR-CVM-04 contextual requirements\n"
        notes += f"• Reachability determined per FRD-CVM-07 definitions\n"
        notes += f"• Impact assessed per FRD-CVM-09 potential adverse impact levels\n"
        
        if context.compensating_controls:
            notes += f"\nCompensating Controls Identified:\n"
            for control in context.compensating_controls:
                notes += f"• {control}\n"
        
        return notes

# External API clients for threat intelligence
class NVDClient:
    """Client for National Vulnerability Database"""
    
    async def get_cvss_score(self, cve_id: str) -> Optional[float]:
        """Get CVSS base score from NVD"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('vulnerabilities'):
                            vuln = data['vulnerabilities'][0]
                            metrics = vuln.get('cve', {}).get('metrics', {})
                            if 'cvssMetricV31' in metrics:
                                return float(metrics['cvssMetricV31'][0]['cvssData']['baseScore'])
                            elif 'cvssMetricV30' in metrics:
                                return float(metrics['cvssMetricV30'][0]['cvssData']['baseScore'])
            return None
        except Exception:
            return None

class EPSSClient:
    """Client for Exploit Prediction Scoring System"""
    
    async def get_epss_score(self, cve_id: str) -> Optional[float]:
        """Get EPSS score for CVE"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('data'):
                            return float(data['data'][0]['epss'])
            return None
        except Exception:
            return None

class CISAKEVClient:
    """Client for CISA Known Exploited Vulnerabilities"""
    
    async def check_kev_status(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV catalog"""
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get('vulnerabilities', [])
                        return any(vuln.get('cveID') == cve_id for vuln in vulnerabilities)
            return False
        except Exception:
            return False

# Global clients
nvd_client = NVDClient()
epss_client = EPSSClient()
cisa_kev_client = CISAKEVClient()

async def get_detectability_score(cve_id: str) -> float:
    """Get detectability score based on vulnerability characteristics"""
    # Mock implementation - would use threat intelligence feeds
    return 0.5

async def get_prevalence_score(cve_id: str) -> float:
    """Get prevalence score based on active exploitation"""
    # Mock implementation - would use threat intelligence feeds
    return 0.3

async def check_patch_availability(cve_id: str) -> bool:
    """Check if patch is available for CVE"""
    # Mock implementation - would check vendor advisories
    return True

async def get_patch_date(cve_id: str) -> Optional[datetime]:
    """Get patch availability date"""
    # Mock implementation - would check vendor advisories
    return datetime.utcnow() + timedelta(days=30) 