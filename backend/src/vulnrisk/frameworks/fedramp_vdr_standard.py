"""
FedRAMP VDR Standard Implementation

Implements the FedRAMP Vulnerability Detection and Response Standard with:
- N1-N5 federal impact classification per FRD-ALL-32 through FRD-ALL-35
- LEV (Likely Exploitable Vulnerability) engine per FRD-ALL-23
- IRV (Internet-Reachable Vulnerability) engine per FRD-ALL-24
- Timeline classification (LEV+IRV, LEV+NIRV, NLEV)
- Machine-readable reporting per FRR-VDR-RP-05
- Corrected context factor evaluation per FRR-VDR-10
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict, Literal

# Type definitions
NRating = Literal['N1', 'N2', 'N3', 'N4', 'N5']

class VDRContext(TypedDict, total=False):
    """Context data for VDR assessment with federal-specific fields"""
    cve_id: str
    # Federal impact assessment fields
    service_degradation_hours: Optional[float]
    federal_data_exposure_percentage: Optional[float]  # 0-100
    estimated_downtime_hours: Optional[float]
    affected_users_percentage: Optional[float]  # 0-100
    
    # Reachability and exploitation
    internet_reachable: bool
    mitigation_effectiveness: float  # 0.0-1.0 (1.0 = fully mitigated)
    epss: float  # 0.0-1.0
    known_exploited: bool
    patch_available: bool
    mission_critical: bool
    asset_contains_federal_data: bool
    
    # Context factors per FRR-VDR-10
    mission_criticality: int  # 1-10 mission importance (NOT CIA)
    reachability_paths: List[str]  # descriptions of feasible threat paths
    # exploitation_likelihood: Derived from EPSS score
    vulnerability_discovery_ease: float  # 0-1 how easy for attacker to find this vuln
    inventory_impact_pct: float  # 0-100 percentage of fleet affected
    granted_privilege_level: str  # none, user, admin, root
    vulnerability_chaining_indicators: List[str]
    threat_intel_tags: List[str]  # KEV, active-campaigns, etc.

@dataclass
class LEVDecision:
    """Likely Exploitable Vulnerability decision per FRD-ALL-23"""
    likely_exploitable: bool
    reasons: List[str]

@dataclass
class IRVDecision:
    """Internet-Reachable Vulnerability decision per FRD-ALL-24"""
    internet_reachable: bool
    payload_triggered_contexts: List[str]
    reasons: List[str]

@dataclass
class TimelineClassification:
    """Timeline classification based on LEV/IRV status and impact rating"""
    category: Literal['LEV+IRV', 'LEV+NIRV', 'NLEV']
    remediation_days: int

@dataclass
class VDRAssessmentResult:
    """Complete VDR assessment result"""
    cve_id: str
    impact_rating: NRating
    lev_decision: LEVDecision
    irv_decision: IRVDecision
    timeline_classification: TimelineClassification
    context_factors: Dict[str, Any]
    incident_response_required: bool
    compliance_report: Dict[str, Any]

class FedRAMPImpactClassifier:
    """
    FRD-ALL-32 through FRD-ALL-35: Mandatory N1-N5 federal impact classification.
    Uses legal thresholds, not business risk mathematics.
    """
    
    def calculate_federal_impact_rating(self, vuln_data: VDRContext) -> NRating:
        """Calculate federal impact rating per FedRAMP definitions"""
        # N5: Catastrophic - 24+ hour service degradation OR majority federal data
        if self._meets_catastrophic_threshold(vuln_data):
            return 'N5'
        
        # N4: Serious - 12+ hour degradation OR minority federal data
        if self._meets_serious_threshold(vuln_data):
            return 'N4'
        
        # Map remaining to legal thresholds
        return self._map_to_legal_thresholds(vuln_data)
    
    def _meets_catastrophic_threshold(self, v: VDRContext) -> bool:
        """N5: Catastrophic impact criteria"""
        # 24+ hour service degradation
        if (v.get('service_degradation_hours') or 0) >= 24:
            return True
        if (v.get('estimated_downtime_hours') or 0) >= 24:
            return True
        
        # Majority federal data exposure
        if (v.get('federal_data_exposure_percentage') or 0) >= 50:
            return True
        
        return False
    
    def _meets_serious_threshold(self, v: VDRContext) -> bool:
        """N4: Serious impact criteria"""
        # 12+ hour service degradation
        if (v.get('service_degradation_hours') or 0) >= 12:
            return True
        if (v.get('estimated_downtime_hours') or 0) >= 12:
            return True
        
        # Minority federal data exposure
        frac = v.get('federal_data_exposure_percentage') or 0
        if 0.0 < frac < 50:
            return True
        
        return False
    
    def _map_to_legal_thresholds(self, v: VDRContext) -> NRating:
        """Map to N3, N2, N1 based on federal definitions"""
        # N3: Material impact to mission but <12h and no federal data
        if (v.get('service_degradation_hours') or 0) >= 4 or v.get('mission_critical', False):
            return 'N3'
        
        # N2: Localized impact, low mission criticality
        if (v.get('service_degradation_hours') or 0) >= 1:
            return 'N2'
        
        # N1: Negligible federal impact
        return 'N1'

def evaluate_fedramp_context_factors(vuln_data: VDRContext) -> Dict[str, Any]:
    """
    FRR-VDR-10 mandatory context evaluation with corrected detectability semantics.
    
    Context factors:
    - criticality: mission criticality (NOT CIA impact)
    - reachability: evaluate threat actor paths (beyond attack vector)
    - exploitability: assess exploitation likelihood
    - detectability: evaluate vulnerability discovery ease (NOT scan detection)
    - prevalence: calculate inventory impact percentage
    - privilege: assess access level granted (separate from criticality)
    - proximate_vulnerabilities: analyze vulnerability chaining
    - known_threats: evaluate threat intelligence
    """
    return {
        'criticality': vuln_data.get('mission_criticality', 5),
        'reachability': {
            'paths': vuln_data.get('reachability_paths', []),
            'is_reachable': bool(vuln_data.get('reachability_paths'))
        },
        'exploitability': vuln_data.get('epss', 0.0),
        'detectability': vuln_data.get('vulnerability_discovery_ease', 0.0),  # FIXED: attacker discovery ease
        'prevalence': vuln_data.get('inventory_impact_pct', 0.0),
        'privilege': vuln_data.get('granted_privilege_level', 'none'),
        'proximate_vulnerabilities': vuln_data.get('vulnerability_chaining_indicators', []),
        'known_threats': vuln_data.get('threat_intel_tags', [])
    }

class FedRAMPVulnerabilityClassifier:
    """
    FedRAMP VDR Standard vulnerability classifier implementing exact federal definitions.
    Replaces existing risk calculator classes with FedRAMP compliance requirements.
    """
    
    def __init__(self, authorization_level: str = "moderate"):
        self.authorization_level = authorization_level.lower()
        self.timeline_matrices = self._initialize_fedramp_timelines()
        
    def _initialize_fedramp_timelines(self) -> Dict[str, Dict[str, Dict[str, int]]]:
        """Exact FedRAMP timeline requirements from VDR Standard"""
        return {
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
    
    def assess_vulnerability_federal_compliance(self, vuln_data: VDRContext) -> VDRAssessmentResult:
        """
        Main assessment method - replaces calculate_risk methods
        Must implement FRR-VDR-07, FRR-VDR-08, FRR-VDR-09, FRR-VDR-10
        """
        
        # Federal impact classification (FRR-VDR-09) - replaces business impact
        impact_level = self._calculate_federal_impact_level(vuln_data)
        
        # Context factors per FRR-VDR-10 (fixes detectability error)
        context_factors = self._evaluate_mandatory_context_factors(vuln_data)
        
        # Likely exploitable per FRD-ALL-23 definition
        is_likely_exploitable = self._assess_likely_exploitable_federal(vuln_data)
        
        # Internet reachable per FRD-ALL-24 definition  
        is_internet_reachable = self._assess_internet_reachable_federal(vuln_data)
        
        # Categorize for timeline calculation
        category = self._determine_vulnerability_category(is_likely_exploitable, is_internet_reachable)
        
        # Calculate mandatory timeline per FedRAMP tables
        timeline_hours = self._get_fedramp_remediation_timeline(impact_level, category)
        
        # Incident response requirement per FRR-VDR-TF-MO-06/HI-06
        requires_incident = self._check_incident_response_requirement(impact_level, category)
        
        # Generate explanation for transparency
        explanation = self._generate_federal_compliance_explanation(
            impact_level, category, context_factors, timeline_hours
        )
        
        return VDRAssessmentResult(
            cve_id=vuln_data.get('cve_id', 'UNKNOWN'),
            impact_rating=impact_level,
            lev_decision=LEVDecision(likely_exploitable=is_likely_exploitable, reasons=[]),
            irv_decision=IRVDecision(internet_reachable=is_internet_reachable, reasons=[], payload_triggered_contexts=[]),
            timeline_classification=TimelineClassification(category=category, remediation_days=timeline_hours // 24),
            context_factors=context_factors,
            incident_response_required=requires_incident,
            compliance_report={}
        )
    
    def _calculate_federal_impact_level(self, vuln_data: VDRContext) -> NRating:
        """
        CRITICAL: Must use exact FRD-ALL-32 through FRD-ALL-35 legal thresholds
        NOT existing business impact scales
        """
        
        # Extract federal-specific metrics
        estimated_downtime = vuln_data.get('estimated_downtime_hours', 0)
        federal_data_exposure_pct = vuln_data.get('federal_data_exposure_percentage', 0)
        service_degradation_hours = vuln_data.get('service_degradation_hours', 0)
        affected_users_pct = vuln_data.get('affected_users_percentage', 0)
        
        # N5: Catastrophic per FRD-ALL-32
        # "24+ hours service degradation OR majority federal data"
        if (estimated_downtime >= 24 or 
            service_degradation_hours >= 24 or
            federal_data_exposure_pct >= 50):
            return 'N5'
            
        # N4: Serious per FRD-ALL-33  
        # "12+ hours degradation OR minority federal data"
        elif (estimated_downtime >= 12 or
              service_degradation_hours >= 12 or
              (federal_data_exposure_pct >= 10 and federal_data_exposure_pct < 50)):
            return 'N4'
            
        # N3: Limited per FRD-ALL-34
        # "Minority users OR small data amount"
        elif (affected_users_pct >= 10 or
              (federal_data_exposure_pct > 0 and federal_data_exposure_pct < 10)):
            return 'N3'
            
        # N2: Negligible per FRD-ALL-35
        # "Few users affected"
        elif affected_users_pct > 0:
            return 'N2'
            
        return 'N1'
    
    def _evaluate_mandatory_context_factors(self, vuln_data: VDRContext) -> Dict[str, float]:
        """
        FRR-VDR-10: All 8 mandatory context factors
        FIXES detectability interpretation error
        """
        
        return {
            'criticality': self._assess_mission_criticality(vuln_data),
            'reachability': self._assess_attack_path_reachability(vuln_data),
            'exploitability': self._assess_exploitation_ease(vuln_data),
            'detectability': self._assess_vulnerability_discovery_ease(vuln_data),  # FIXED
            'prevalence': self._calculate_affected_inventory_percentage(vuln_data),
            'privilege': self._assess_privilege_escalation_level(vuln_data),
            'proximate_vulnerabilities': self._analyze_vulnerability_chaining(vuln_data),
            'known_threats': self._evaluate_current_threat_intelligence(vuln_data)
        }
    
    def _assess_vulnerability_discovery_ease(self, vuln_data: VDRContext) -> float:
        """
        CRITICAL FIX: Detectability = how easily attackers discover vulnerability exists
        NOT how to detect someone scanning your systems
        """
        
        discovery_ease_score = 0.0
        
        # High detectability - easily discoverable by attackers
        if vuln_data.get('known_exploited', False):
            discovery_ease_score += 0.4  # Known exploited = high discoverability
        if vuln_data.get('threat_intel_tags', []) and 'cisa_kev' in vuln_data.get('threat_intel_tags', []):
            discovery_ease_score += 0.3  # CISA KEV = public knowledge
        if vuln_data.get('epss', 0.0) > 0.5:
            discovery_ease_score += 0.2  # High EPSS = likely public
        
        # Medium detectability - requires some effort
        if vuln_data.get('internet_reachable', False):
            discovery_ease_score += 0.1  # Internet reachable = easier to find
        
        # Use provided discovery ease if available
        if 'vulnerability_discovery_ease' in vuln_data:
            discovery_ease_score = max(discovery_ease_score, vuln_data['vulnerability_discovery_ease'])
        
        return min(discovery_ease_score, 1.0)
    
    def _assess_likely_exploitable_federal(self, vuln_data: VDRContext) -> bool:
        """
        FRD-ALL-23: LEV requires ALL three conditions:
        1. NOT fully mitigated
        2. Reachable by likely threat actor  
        3. Likely successful exploitation
        """
        
        # Condition 1: Not fully mitigated per FRD-ALL-28
        mitigation_effectiveness = vuln_data.get('mitigation_effectiveness', 0.0)
        not_fully_mitigated = mitigation_effectiveness < 0.95
        
        # Condition 2: Reachable by likely threat actor
        threat_actor_can_reach = self._assess_threat_actor_reachability(vuln_data)
        
        # Condition 3: Likely successful exploitation
        exploitation_likely = self._assess_exploitation_success_probability(vuln_data)
        
        # ALL three must be true for LEV classification
        return not_fully_mitigated and threat_actor_can_reach and exploitation_likely
    
    def _assess_threat_actor_reachability(self, vuln_data: VDRContext) -> bool:
        """Assess if likely threat actors can reach this vulnerability"""
        
        reachability_factors = [
            vuln_data.get('internet_reachable', False),
            bool(vuln_data.get('reachability_paths', [])),
            vuln_data.get('asset_contains_federal_data', False)
        ]
        
        # If any path exists, it's reachable
        return any(reachability_factors)
    
    def _assess_exploitation_success_probability(self, vuln_data: VDRContext) -> bool:
        """Assess likelihood of successful exploitation"""
        
        success_indicators = []
        
        # High probability indicators
        if vuln_data.get('epss', 0.0) > 0.1:
            success_indicators.append(0.4)
        if vuln_data.get('known_exploited', False):
            success_indicators.append(0.3)
        if 'cisa_kev' in vuln_data.get('threat_intel_tags', []):
            success_indicators.append(0.5)
        if vuln_data.get('epss', 0.0) >= 0.5:
            success_indicators.append(0.2)
            
        # Calculate probability
        total_probability = sum(success_indicators)
        return total_probability >= 0.5  # 50% threshold for "likely"
    
    def _assess_internet_reachable_federal(self, vuln_data: VDRContext) -> bool:
        """
        FRD-ALL-24: Internet-reachable = can be triggered by payload from internet
        Includes systems that process internet payloads even if not directly accessible
        """
        
        # Direct internet accessibility
        if vuln_data.get('internet_reachable', False):
            return True
            
        # Indirect reachability - processes payloads from internet sources
        payload_processing_paths = [
            'unauthenticated_http' in vuln_data.get('reachability_paths', []),
            'unauthenticated_https' in vuln_data.get('reachability_paths', []),
            'web_interface' in vuln_data.get('reachability_paths', []),
            'api_endpoint' in vuln_data.get('reachability_paths', [])
        ]
        
        return any(payload_processing_paths)
    
    def _determine_vulnerability_category(self, is_likely_exploitable: bool, is_internet_reachable: bool) -> str:
        """Determine vulnerability category for timeline calculation"""
        if is_likely_exploitable and is_internet_reachable:
            return 'LEV_IRV'
        elif is_likely_exploitable and not is_internet_reachable:
            return 'LEV_NIRV'
        else:
            return 'NLEV'
    
    def _get_fedramp_remediation_timeline(self, impact_level: NRating, category: str) -> int:
        """Get exact FedRAMP timeline in hours"""
        # Safe lookup with fallbacks to avoid KeyError for unmodeled N-ratings (e.g., N1)
        timeline_days = (
            self.timeline_matrices
                .get(self.authorization_level, {})
                .get(impact_level, {})
                .get(category)
        )
        if timeline_days is None:
            # Conservative fallbacks aligned with FRR-VDR timeframes
            fallback_days = {
                'LEV_IRV': 3,   # internet-reachable likely exploitable
                'LEV_NIRV': 7,  # not internet-reachable likely exploitable
                'NLEV': 192     # all other vulnerabilities (cap aligns with acceptance threshold)
            }
            timeline_days = fallback_days.get(category, 180)
        return int(timeline_days * 24)  # Convert to hours
    
    def _check_incident_response_requirement(self, impact_level: NRating, category: str) -> bool:
        """
        Per FRR-VDR-TF-MO-06 and FRR-VDR-TF-HI-06
        N4/N5 LEV+IRV requires incident response
        """
        
        if category == 'LEV_IRV':
            if impact_level in ['N4', 'N5']:
                return True
                
        # High authorization also requires incident response for N5 internal
        if (self.authorization_level == 'high' and 
            impact_level == 'N5' and
            category == 'LEV_NIRV'):
            return True
            
        return False
    
    def _assess_mission_criticality(self, vuln_data: VDRContext) -> float:
        """Assess mission criticality level"""
        return vuln_data.get('mission_criticality', 5) / 10.0
    
    def _assess_attack_path_reachability(self, vuln_data: VDRContext) -> float:
        """Assess attack path reachability"""
        return 1.0 if vuln_data.get('internet_reachable', False) else 0.5
    
    def _assess_exploitation_ease(self, vuln_data: VDRContext) -> float:
        """Assess exploitation ease"""
        return vuln_data.get('epss', 0.0)
    
    def _calculate_affected_inventory_percentage(self, vuln_data: VDRContext) -> float:
        """Calculate affected inventory percentage"""
        return vuln_data.get('inventory_impact_pct', 0.0) / 100.0
    
    def _assess_privilege_escalation_level(self, vuln_data: VDRContext) -> float:
        """Assess privilege escalation level"""
        privilege_levels = {'none': 0.0, 'user': 0.3, 'admin': 0.7, 'root': 1.0}
        return privilege_levels.get(vuln_data.get('granted_privilege_level', 'none'), 0.0)
    
    def _analyze_vulnerability_chaining(self, vuln_data: VDRContext) -> float:
        """Analyze vulnerability chaining potential"""
        chaining_indicators = vuln_data.get('vulnerability_chaining_indicators', [])
        return min(len(chaining_indicators) * 0.2, 1.0)
    
    def _evaluate_current_threat_intelligence(self, vuln_data: VDRContext) -> float:
        """Evaluate current threat intelligence"""
        threat_tags = vuln_data.get('threat_intel_tags', [])
        return min(len(threat_tags) * 0.3, 1.0)
    
    def _generate_federal_compliance_explanation(self, impact_level: NRating, category: str, 
                                               context_factors: Dict[str, float], timeline_hours: int) -> str:
        """Generate federal compliance explanation"""
        return f"Federal Impact: {impact_level}, Category: {category}, Timeline: {timeline_hours} hours"

class LEVEngine:
    """
    FRD-ALL-23: Likely Exploitable Vulnerability (LEV) Engine
    
    Definition: A vulnerability where a likely threat actor with knowledge 
    of the vulnerability would likely be able to gain unauthorized access, 
    cause harm, disrupt operations, or otherwise have an undesired adverse impact.
    
    Three-condition validation: not fully mitigated AND reachable AND likely exploitation
    """
    
    def assess(self, v: VDRContext) -> LEVDecision:
        """Assess if vulnerability is likely exploitable per FRD-ALL-23"""
        reasons: List[str] = []
        
        # Condition 1: Not fully mitigated
        not_fully_mitigated = (v.get('mitigation_effectiveness', 0.0) < 0.95)
        if not_fully_mitigated:
            reasons.append('not_fully_mitigated')
        
        # Condition 2: Reachable
        reachable = bool(
            v.get('internet_reachable', False) or 
            v.get('reachability_paths', []) or
            v.get('asset_contains_federal_data', False)
        )
        if reachable:
            reasons.append('reachable')
        
        # Condition 3: Likely exploitation
        likely_exploitation = bool(
            (v.get('epss', 0.0) >= 0.2) or
            v.get('known_exploited', False) or
            (v.get('epss', 0.0) >= 0.5) or
            'KEV' in (v.get('threat_intel_tags', []))
        )
        if likely_exploitation:
            reasons.append('likely_exploitation')
        
        decision = not_fully_mitigated and reachable and likely_exploitation
        return LEVDecision(likely_exploitable=decision, reasons=reasons)

class IRVEngine:
    """
    FRD-ALL-24: Internet-Reachable Vulnerability (IRV) Assessment
    
    Must implement payload-triggered scenarios beyond simple network accessibility.
    Considers various attack vectors that can reach internet-facing systems.
    """
    
    PAYLOAD_SCENARIOS = (
        'unauthenticated_http', 'exposed_api', 'email_attachment',
        'dns_payload', 'supply_chain_artifact', 'drive_by_download',
        'web_interface', 'api_endpoint', 'file_upload'
    )
    
    def assess(self, v: VDRContext) -> IRVDecision:
        """Assess if vulnerability is internet-reachable per FRD-ALL-24"""
        reasons: List[str] = []
        contexts: List[str] = []
        
        # Direct internet reachability
        is_inet = bool(v.get('internet_reachable', False))
        if is_inet:
            reasons.append('asset_internet_reachable')
        
        # Payload-triggered scenarios
        for path in v.get('reachability_paths', []):
            p = str(path).lower()
            if any(scenario in p for scenario in self.PAYLOAD_SCENARIOS):
                contexts.append(p)
        
        if contexts:
            reasons.append('payload_triggered_reachable')
        
        # Consider federal data exposure as internet reachable
        if v.get('asset_contains_federal_data', False) and is_inet:
            reasons.append('federal_data_internet_exposed')
        
        return IRVDecision(
            internet_reachable=is_inet or bool(contexts),
            payload_triggered_contexts=contexts,
            reasons=reasons
        )

class TimelineEngine:
    """
    Timeline classification using exact FedRAMP timeframe tables per authorization level.
    Implements exact FedRAMP timeline requirements from VDR Standard.
    """
    
    def __init__(self, authorization_level: str = "moderate"):
        self.authorization_level = authorization_level.lower()
        self.timeline_matrices = self._initialize_fedramp_timelines()
    
    def _initialize_fedramp_timelines(self) -> Dict[str, Dict[str, Dict[str, int]]]:
        """Exact FedRAMP timeline requirements from VDR Standard"""
        return {
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
    
    def classify(self, lev: LEVDecision, irv: IRVDecision, n_rating: NRating) -> TimelineClassification:
        """Classify remediation timeline based on LEV/IRV status and impact rating using exact FedRAMP matrices"""
        
        # Determine category
        if lev.likely_exploitable and irv.internet_reachable:
            category = 'LEV_IRV'
        elif lev.likely_exploitable and not irv.internet_reachable:
            category = 'LEV_NIRV'
        else:
            category = 'NLEV'
        
        # Get timeline from matrix with safe fallback to avoid KeyError (e.g., N1)
        timeline_days = (
            self.timeline_matrices
                .get(self.authorization_level, {})
                .get(n_rating, {})
                .get(category)
        )
        if timeline_days is None:
            fallback_days = {
                'LEV_IRV': 3,
                'LEV_NIRV': 7,
                'NLEV': 192
            }
            timeline_days = fallback_days.get(category, 180)
        
        return TimelineClassification(category=category, remediation_days=int(timeline_days))

class FedRAMPReportingAPI:
    """
    FRR-VDR-RP-05: Machine-readable reporting fields for federal agency access.
    Generates compliance reports that can be consumed by federal oversight systems.
    """
    
    def __init__(self):
        pass
    
    def generate_vdr_compliant_report(
        self, 
        ctx: VDRContext, 
        classifier: FedRAMPImpactClassifier,
        lev: LEVDecision, 
        irv: IRVDecision,
        timeline: TimelineClassification
    ) -> Dict[str, Any]:
        """Generate machine-readable VDR compliance report per FRR-VDR-RP-05"""
        
        return {
            'provider_tracking_id': self.generate_internal_id(ctx),
            'detection_time_source': self.get_detection_metadata(),
            'evaluation_completion_time': self.get_triage_timestamp(),
            'internet_reachable_status': irv.internet_reachable,
            'likely_exploitable_status': lev.likely_exploitable,
            'historical_impact_estimates': self.track_impact_changes(ctx.get('cve_id')),
            'current_impact_estimates': self.calculate_current_n_rating(classifier, ctx),
            'mitigation_timeline_targets': timeline.remediation_days,
            'overdue_status_explanation': self.explain_overdue_vulns([]),
            'supplementary_information': self.compile_additional_context(ctx),
            'final_disposition': self.determine_vulnerability_outcome(lev, timeline),
        }
    
    def generate_internal_id(self, ctx: VDRContext) -> str:
        """Generate internal tracking ID for VDR assessment"""
        cve = ctx.get('cve_id', 'UNKNOWN')
        return f"VDR-{cve}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    def get_detection_metadata(self) -> Dict[str, Any]:
        """Get detection source metadata"""
        return {
            'source': 'scanner|intel|manual',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def get_triage_timestamp(self) -> str:
        """Get triage completion timestamp"""
        return datetime.utcnow().isoformat()
    
    def track_impact_changes(self, cve_id: Optional[str]) -> List[Dict[str, Any]]:
        """Track historical impact changes for CVE"""
        # Placeholder - integrate with historical data store
        return []
    
    def calculate_current_n_rating(self, classifier: FedRAMPImpactClassifier, ctx: VDRContext) -> NRating:
        """Calculate current N-rating for report"""
        return classifier.calculate_federal_impact_rating(ctx)
    
    def get_remediation_timeline(self) -> Dict[str, Any]:
        """Get remediation timeline information"""
        return {}
    
    def explain_overdue_vulns(self, records: List[Dict[str, Any]]) -> str:
        """Explain overdue vulnerability status"""
        return ""
    
    def compile_additional_context(self, ctx: VDRContext) -> Dict[str, Any]:
        """Compile additional context information"""
        return {
            'context_factors': evaluate_fedramp_context_factors(ctx),
            'federal_data_fields': {
                'service_degradation_hours': ctx.get('service_degradation_hours'),
                'federal_data_exposure_percentage': ctx.get('federal_data_exposure_percentage'),
                'estimated_downtime_hours': ctx.get('estimated_downtime_hours'),
                'affected_users_percentage': ctx.get('affected_users_percentage'),
            }
        }
    
    def determine_vulnerability_outcome(self, lev: LEVDecision, timeline: TimelineClassification) -> str:
        """Determine final vulnerability disposition"""
        if lev.likely_exploitable and timeline.remediation_days <= 7:
            return 'accepted_for_remediation'
        return 'tracked'

class VDRAssessmentEngine:
    """
    Main VDR assessment engine that orchestrates all components
    """
    
    def __init__(self, authorization_level: str = "moderate"):
        self.classifier = FedRAMPImpactClassifier()
        self.lev_engine = LEVEngine()
        self.irv_engine = IRVEngine()
        self.timeline_engine = TimelineEngine(authorization_level)
        self.reporting_api = FedRAMPReportingAPI()
        self.fedramp_classifier = FedRAMPVulnerabilityClassifier(authorization_level)
    
    def assess_vulnerability(self, ctx: VDRContext) -> VDRAssessmentResult:
        """Perform complete VDR assessment using FedRAMP compliance classifier"""
        
        # Use the comprehensive FedRAMP classifier for full compliance
        return self.fedramp_classifier.assess_vulnerability_federal_compliance(ctx)
    
    def _requires_incident_response(
        self, 
        lev: LEVDecision, 
        irv: IRVDecision, 
        n_rating: NRating, 
        ctx: VDRContext
    ) -> bool:
        """Determine if incident response is required per FedRAMP requirements"""
        
        # LEV+IRV always requires incident response
        if lev.likely_exploitable and irv.internet_reachable:
            return True
        
        # LEV with high impact ratings
        if lev.likely_exploitable and n_rating in ('N5', 'N4'):
            return True
        
        # Known exploited vulnerabilities
        if ctx.get('known_exploited', False):
            return True
        
        # KEV listed vulnerabilities
        if 'KEV' in ctx.get('threat_intel_tags', []):
            return True
        
        return False
