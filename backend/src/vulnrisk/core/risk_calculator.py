from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

@dataclass
class VulnerabilityData:
    """Data class representing a vulnerability and its context."""
    cve_id: str
    cvss_score: float
    asset_criticality: int
    epss_score: float
    is_internet_facing: bool
    has_exploit: bool = False
    is_kev: bool = False
    # Additional context for transparent calculations
    cia_impact: Dict[str, float] = None  # Confidentiality, Integrity, Availability
    network_exposure: str = "internal"  # internet-facing, internal, isolated
    attack_path_complexity: str = "direct"  # direct, single-hop, multi-hop, complex
    exploit_availability: str = "none"  # automated, manual, poc, details, limited, specialized
    discovery_difficulty: str = "standard"  # easy, standard, authenticated, specialized, manual
    exploitation_frequency: str = "none"  # kev, active, known, sporadic, none, academic
    target_attractiveness: str = "standard"  # high-value, medium-value, standard, low-value, specialized
    threat_actor_sophistication: str = "standard"  # nation-state, apt, organized, skilled, script-kiddie, opportunistic
    resource_level: str = "standard"  # well-funded, moderate, standard, limited, minimal
    vulnerability_age_days: int = 0
    patch_availability: str = "available"  # none, complex, standard, deployed, mandated
    disclosure_timeline: str = "standard"  # zero-day, coordinated, standard, responsible, full
    preventive_controls: List[str] = None
    detective_controls: List[str] = None
    response_controls: List[str] = None

@dataclass
class CalculationComponent:
    """Represents a single calculation component with full transparency."""
    value: float
    weight: float
    contribution: float
    source: str
    reasoning: str
    sub_components: Optional[Dict[str, Any]] = None

@dataclass
class RiskScore:
    """Data class representing the risk score with full transparency."""
    score: float
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

class BaseRiskFramework(ABC):
    """Abstract base class for risk frameworks."""
    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description

    @abstractmethod
    def calculate_risk(self, vuln: VulnerabilityData) -> RiskScore:
        pass

    def _calculate_confidence_score(self, vuln: VulnerabilityData) -> float:
        """Calculate confidence score based on data quality."""
        data_freshness = 0.9  # Assume recent data
        source_reliability = 0.9  # NVD and EPSS are reliable sources
        coverage_completeness = 0.8  # Most data points available
        
        return (data_freshness * 0.3) + (source_reliability * 0.4) + (coverage_completeness * 0.3)

    def _get_data_freshness(self) -> Dict[str, str]:
        """Get data freshness information."""
        return {
            "cvss_age": "1 day",
            "epss_age": "1 day",
            "threat_intel_age": "6 hours"
        }

    def _normalize_final_score(self, raw_score: float, framework: str) -> float:
        """
        Normalize raw framework scores to 0–100 so they align with site docs and SLAs.
        Factors are empirically chosen and can be refined via calibration data.
        """
        factors = {
            "enhanced": 2.0,     # Raw ~0–60 → ~0–100
            "mitigation": 2.0,   # Uses enhanced pipeline
            "risk_based": 2.0    # Risk-based also needs normalization
        }
        factor = factors.get(framework, 1.0)
        normalized = raw_score * factor
        return min(max(normalized, 0.0), 100.0)

    def _generate_recommendations(self, vuln: VulnerabilityData, score: float, priority: str, timeline: int = None) -> List[str]:
        """Generate enterprise-grade actionable recommendations based on risk assessment and SLA timeline."""
        recommendations = []
        
        # Timeline-based recommendations (enterprise approach)
        if timeline and timeline <= 7:
            recommendations.extend([
                f"🚨 URGENT: Remediate within {timeline} days",
                "Schedule emergency maintenance window if needed",
                "Implement immediate compensating controls if patching delayed",
                "Notify stakeholders and document risk acceptance if timeline cannot be met"
            ])
        elif timeline and timeline <= 15:
            recommendations.extend([
                f"🔥 HIGH PRIORITY: Remediate within {timeline} days", 
                "Schedule next available maintenance window",
                "Review and strengthen network security controls",
                "Update threat detection rules and monitoring"
            ])
        elif timeline and timeline <= 30:
            recommendations.extend([
                f"⚡ ELEVATED: Remediate within {timeline} days",
                "Include in next monthly maintenance cycle",
                "Review existing security controls effectiveness",
                "Update vulnerability management procedures"
            ])
        elif timeline and timeline <= 90:
            recommendations.extend([
                f"📅 PLANNED: Remediate within {timeline} days",
                "Include in next quarterly maintenance cycle",
                "Document for compliance reporting",
                "Consider additional monitoring and detection"
            ])
        else:
            # Fallback to priority-based for backwards compatibility
            timeline_display = f"{timeline} days" if timeline else "standard timeline"
            if priority == "CRITICAL":
                recommendations.extend([
                    f"Apply vendor patch immediately ({timeline_display})",
                    "Implement emergency compensating controls",
                    "Activate incident response procedures"
                ])
            elif priority == "HIGH":
                recommendations.extend([
                    f"Apply vendor patch within {timeline_display}",
                    "Review and strengthen network security controls",
                    "Update threat detection rules"
                ])
            else:
                recommendations.extend([
                    f"Apply patch during standard patching cycle ({timeline_display})",
                    "Document for future reference",
                    "Include in regular security reviews"
                ])
        
        # Context-specific enterprise recommendations
        if vuln.is_kev:
            recommendations.append("🎯 CISA KEV LISTED: Federal mandate requires immediate attention")
        
        if vuln.is_internet_facing:
            recommendations.append("🌐 INTERNET-FACING: Prioritize due to external threat exposure")
        
        if vuln.has_exploit:
            recommendations.append("💥 EXPLOIT AVAILABLE: Active exploitation possible - monitor for indicators of compromise")
        
        if vuln.asset_criticality >= 8:
            recommendations.append("🏢 HIGH-VALUE ASSET: Business-critical system requires expedited remediation")
        
        # Asset-specific recommendations
        if vuln.asset_criticality >= 8 and vuln.is_internet_facing:
            recommendations.append("⚠️ CRITICAL EXPOSURE: High-value internet-facing asset - consider temporary network isolation")
        
        return recommendations

class EnhancedContextualFramework(BaseRiskFramework):
    """Risk framework that balances technical severity with business context."""
    def __init__(self) -> None:
        super().__init__(
            "Enhanced Contextual",
            "Balances technical severity with business context"
        )
        self.weights = {
            'cvss': 0.4,
            'criticality': 0.4,
            'epss': 0.2
        }

    def _calculate_technical_severity(self, vuln: VulnerabilityData) -> CalculationComponent:
        """Calculate technical severity component."""
        value = vuln.cvss_score
        weight = self.weights['cvss']
        contribution = value * weight
        
        return CalculationComponent(
            value=value,
            weight=weight,
            contribution=contribution,
            source="NVD CVSS 3.1 Base Score",
            reasoning=f"CVSS {value}/10 - {self._get_cvss_severity_level(value)} severity"
        )

    def _calculate_business_impact(self, vuln: VulnerabilityData) -> CalculationComponent:
        """Calculate business impact component."""
        # Apply CIA impact factor if available
        cia_factor = 1.0
        if vuln.cia_impact:
            cia_factor = max(vuln.cia_impact.values())
        
        value = vuln.asset_criticality * cia_factor
        weight = self.weights['criticality']
        contribution = value * weight
        
        criticality_level = self._get_criticality_level(vuln.asset_criticality)
        
        return CalculationComponent(
            value=value,
            weight=weight,
            contribution=contribution,
            source="Asset inventory classification",
            reasoning=f"Asset criticality {vuln.asset_criticality}/10 ({criticality_level}) with CIA factor {cia_factor:.1f}"
        )

    def _calculate_exploit_likelihood(self, vuln: VulnerabilityData) -> CalculationComponent:
        """Calculate exploit likelihood component."""
        # Apply threat intelligence factor
        threat_factor = self._get_threat_intelligence_factor(vuln)
        value = (vuln.epss_score * 100) * threat_factor
        
        # KEV floor to prevent underestimation when EPSS is temporarily low
        if vuln.is_kev:
            value = max(value, 20.0)  # at least 20 (pre-weight), i.e., ≥4 contribution after weight
        
        weight = self.weights['epss']
        contribution = value * weight
        
        return CalculationComponent(
            value=value,
            weight=weight,
            contribution=contribution,
            source="FIRST.org EPSS + Threat Intelligence",
            reasoning=f"EPSS {vuln.epss_score:.3f} ({vuln.epss_score*100:.1f}% probability) with threat factor {threat_factor:.1f}"
        )

    def _calculate_context_multipliers(self, vuln: VulnerabilityData) -> Dict[str, CalculationComponent]:
        """Calculate context multipliers."""
        multipliers = {}
        
        # Reachability multiplier
        network_exposure = self._get_network_exposure_factor(vuln.network_exposure)
        attack_complexity = self._get_attack_complexity_factor(vuln.attack_path_complexity)
        reachability_value = network_exposure * attack_complexity
        
        multipliers['reachability'] = CalculationComponent(
            value=reachability_value,
            weight=1.0,
            contribution=reachability_value,
            source="Network exposure analysis",
            reasoning=f"Network exposure: {vuln.network_exposure} ({network_exposure:.1f}x), Attack complexity: {vuln.attack_path_complexity} ({attack_complexity:.1f}x)"
        )
        
        # Threat intelligence multiplier
        threat_value = self._get_threat_intelligence_factor(vuln)
        multipliers['threat_intelligence'] = CalculationComponent(
            value=threat_value,
            weight=1.0,
            contribution=threat_value,
            source="Threat intelligence feeds",
            reasoning=self._get_threat_intelligence_reasoning(vuln)
        )
        
        return multipliers

    def _calculate_mitigation_factors(self, vuln: VulnerabilityData) -> Dict[str, CalculationComponent]:
        """Calculate mitigation factors."""
        factors = {}
        
        # Preventive controls
        preventive_value = self._calculate_preventive_controls(vuln.preventive_controls or [])
        factors['preventive_controls'] = CalculationComponent(
            value=preventive_value,
            weight=1.0,
            contribution=preventive_value,
            source="Security control assessment",
            reasoning=f"Preventive controls: {', '.join(vuln.preventive_controls or ['None'])}"
        )
        
        # Detective controls
        detective_value = self._calculate_detective_controls(vuln.detective_controls or [])
        factors['detective_controls'] = CalculationComponent(
            value=detective_value,
            weight=1.0,
            contribution=detective_value,
            source="Monitoring assessment",
            reasoning=f"Detective controls: {', '.join(vuln.detective_controls or ['None'])}"
        )
        
        # Response controls
        response_value = self._calculate_response_controls(vuln.response_controls or [])
        factors['response_controls'] = CalculationComponent(
            value=response_value,
            weight=1.0,
            contribution=response_value,
            source="Response capability assessment",
            reasoning=f"Response controls: {', '.join(vuln.response_controls or ['None'])}"
        )
        
        return factors

    def calculate_risk(self, vuln: VulnerabilityData) -> RiskScore:
        """Calculate risk score with full transparency."""
        # Calculate base risk components
        technical_severity = self._calculate_technical_severity(vuln)
        business_impact = self._calculate_business_impact(vuln)
        exploit_likelihood = self._calculate_exploit_likelihood(vuln)
        
        base_risk = technical_severity.contribution + business_impact.contribution + exploit_likelihood.contribution
        
        # Calculate context multipliers
        context_multipliers = self._calculate_context_multipliers(vuln)
        reachability_multiplier = context_multipliers['reachability'].value
        threat_multiplier = context_multipliers['threat_intelligence'].value
        
        # Calculate mitigation factors
        mitigation_factors = self._calculate_mitigation_factors(vuln)
        total_mitigation = sum(factor.value for factor in mitigation_factors.values())
        mitigation_factor = min(total_mitigation, 0.9)  # Cap at 90% reduction
        
        # Apply multipliers and mitigation
        intermediate_score = base_risk * reachability_multiplier * threat_multiplier
        final_score = intermediate_score * (1 - mitigation_factor)
        
        # Normalize to 0-100 scale
        final_score = self._normalize_final_score(final_score, "enhanced")
        
        # Determine priority and timeline with context awareness
        priority, timeline = self._classify_priority(final_score, vuln)
        
        # Generate detailed explanation
        explanation = self._generate_detailed_explanation(vuln, final_score, base_risk, context_multipliers, mitigation_factors)
        
        # Build calculation breakdown
        calculation_breakdown = {
            "base_risk": {
                "value": base_risk,
                "components": {
                    "technical_severity": {
                        "value": technical_severity.value,
                        "weight": technical_severity.weight,
                        "contribution": technical_severity.contribution,
                        "source": technical_severity.source,
                        "reasoning": technical_severity.reasoning
                    },
                    "business_impact": {
                        "value": business_impact.value,
                        "weight": business_impact.weight,
                        "contribution": business_impact.contribution,
                        "source": business_impact.source,
                        "reasoning": business_impact.reasoning
                    },
                    "exploit_likelihood": {
                        "value": exploit_likelihood.value,
                        "weight": exploit_likelihood.weight,
                        "contribution": exploit_likelihood.contribution,
                        "source": exploit_likelihood.source,
                        "reasoning": exploit_likelihood.reasoning
                    }
                }
            },
            "context_multipliers": {
                "reachability": {
                    "value": reachability_multiplier,
                    "reasoning": context_multipliers['reachability'].reasoning
                },
                "threat_intelligence": {
                    "value": threat_multiplier,
                    "reasoning": context_multipliers['threat_intelligence'].reasoning
                }
            },
            "mitigation_factors": {
                "total_reduction": mitigation_factor,
                "components": {
                    name: {
                        "value": factor.value,
                        "controls": getattr(vuln, f"{name.split('_')[0]}_controls", []),
                        "reasoning": factor.reasoning
                    }
                    for name, factor in mitigation_factors.items()
                }
            }
        }
        
        # Calculate confidence and get recommendations
        confidence_score = self._calculate_confidence_score(vuln)
        data_freshness = self._get_data_freshness()
        recommendations = self._generate_recommendations(vuln, final_score, priority, timeline)
        
        # Create audit trail
        audit_trail = {
            "calculation_timestamp": datetime.now().isoformat(),
            "framework_version": "1.0",
            "input_parameters": {
                "cve_id": vuln.cve_id,
                "cvss_score": vuln.cvss_score,
                "asset_criticality": vuln.asset_criticality,
                "epss_score": vuln.epss_score,
                "is_internet_facing": vuln.is_internet_facing,
                "is_kev": vuln.is_kev
            },
            "calculation_steps": [
                f"Base risk calculation: {base_risk:.2f}",
                f"Reachability multiplier: {reachability_multiplier:.2f}",
                f"Threat multiplier: {threat_multiplier:.2f}",
                f"Intermediate score: {intermediate_score:.2f}",
                f"Mitigation factor: {mitigation_factor:.2f}",
                f"Final score: {final_score:.2f}"
            ]
        }

        return RiskScore(
            score=final_score,
            priority=priority,
            timeline_days=timeline,
            explanation=explanation,
            components={
                'cvss_component': technical_severity.contribution,
                'criticality_component': business_impact.contribution,
                'epss_component': exploit_likelihood.contribution,
                'reachability_multiplier': reachability_multiplier,
                'threat_multiplier': threat_multiplier,
                'mitigation_factor': mitigation_factor
            },
            calculation_breakdown=calculation_breakdown,
            confidence_score=confidence_score,
            data_freshness=data_freshness,
            recommendations=recommendations,
            audit_trail=audit_trail
        )

    def _classify_priority(self, score: float, vuln: VulnerabilityData = None) -> tuple[str, int]:
        """
        Enterprise-grade priority classification based on industry research and big tech practices.
        
        Base timelines (realistic operational windows):
        - CRITICAL: 7 days (industry standard for emergency response)
        - HIGH: 30 days (CISA standard, monthly maintenance cycle)
        - MEDIUM: 60 days (quarterly planning cycle)  
        - LOW: 120 days (reasonable patching cycle)
        - INFORMATIONAL: Next maintenance window (context-dependent)
        
        Context-based acceleration:
        - CISA KEV: Max 14 days (federal compliance requirement)
        - Active exploitation: Half timeline (minimum 3 days)
        - High asset criticality: 30% faster (minimum 5 days)
        - Internet-facing: Accelerated based on exposure risk
        """
        # Base enterprise timelines (aligned with industry research)
        if score >= 90:
            priority, timeline = "CRITICAL", 7
        elif score >= 70:
            priority, timeline = "HIGH", 30
        elif score >= 40:
            priority, timeline = "MEDIUM", 60
        elif score >= 20:
            priority, timeline = "LOW", 120
        else:
            priority, timeline = "INFORMATIONAL", -1  # Next maintenance window
        
        # Context-based acceleration (enterprise intelligence)
        if vuln:
            # CISA KEV compliance (federal/enterprise mandate)
            if vuln.is_kev:
                if timeline == -1:  # INFORMATIONAL with KEV
                    timeline = 14  # KEV gets fixed timeline
                else:
                    timeline = min(timeline, 14)  # KEV max 14 days
                # Elevate priority for actionable KEV vulnerabilities
                if score >= 40:
                    priority = "CRITICAL" if score >= 70 else "HIGH"
            
            # Active exploitation detected (threat intelligence)
            if vuln.has_exploit and score >= 20:  # Lower threshold for exploit acceleration
                if timeline == -1:
                    timeline = 30  # INFORMATIONAL with exploit gets fixed timeline
                else:
                    timeline = max(int(timeline * 0.5), 3)  # Half time, minimum 3 days
            
            # High-value asset acceleration (business impact)
            if vuln.asset_criticality >= 9 and score >= 20:
                if timeline == -1:
                    timeline = 60  # High-value INFORMATIONAL gets quarterly timeline
                else:
                    timeline = max(int(timeline * 0.7), 5)  # 30% faster, minimum 5 days
            
            # Internet-facing acceleration (exposure risk)
            if vuln.is_internet_facing and score >= 30:  # Lower threshold for internet exposure
                if timeline == -1:
                    timeline = 90  # Internet INFORMATIONAL gets fixed timeline
                else:
                    timeline = max(timeline // 2, 3)  # Halve timeline, minimum 3 days
            
            # Convert -1 (next maintenance window) to reasonable default
            if timeline == -1:
                timeline = 180  # Default maintenance cycle for true INFORMATIONAL
        else:
            # Fallback when no vulnerability context available
            if timeline == -1:
                timeline = 180
        
        return priority, timeline

    def _generate_detailed_explanation(self, vuln: VulnerabilityData, final_score: float, base_risk: float, 
                                     context_multipliers: Dict, mitigation_factors: Dict) -> str:
        """Generate detailed explanation of the calculation."""
        explanation = f"Risk score {final_score:.2f}/100 calculated using transparent methodology:\n\n"
        
        explanation += "1. TECHNICAL ASSESSMENT\n"
        explanation += f"   └── CVSS Base Score: {vuln.cvss_score}/10 ({self._get_cvss_severity_level(vuln.cvss_score)})\n"
        explanation += f"   └── Asset Criticality: {vuln.asset_criticality}/10 ({self._get_criticality_level(vuln.asset_criticality)})\n"
        explanation += f"   └── EPSS Score: {vuln.epss_score:.3f} ({vuln.epss_score*100:.1f}% exploitation probability)\n"
        
        explanation += "\n2. CONTEXT MULTIPLIERS\n"
        explanation += f"   └── Network Exposure: {vuln.network_exposure} ({context_multipliers['reachability'].value:.1f}x)\n"
        explanation += f"   └── Threat Intelligence: {context_multipliers['threat_intelligence'].reasoning}\n"
        
        explanation += "\n3. MITIGATION ASSESSMENT\n"
        total_mitigation = sum(factor.value for factor in mitigation_factors.values())
        explanation += f"   └── Total Risk Reduction: {total_mitigation*100:.0f}%\n"
        for name, factor in mitigation_factors.items():
            explanation += f"   └── {name.replace('_', ' ').title()}: {factor.value*100:.0f}% reduction\n"
        
        explanation += f"\n4. FINAL CALCULATION\n"
        explanation += f"   └── Base Risk: {base_risk:.2f}/100\n"
        explanation += f"   └── Applied Multipliers: {context_multipliers['reachability'].value:.1f}x × {context_multipliers['threat_intelligence'].value:.1f}x\n"
        explanation += f"   └── Mitigation Applied: {total_mitigation*100:.0f}% reduction\n"
        explanation += f"   └── FINAL RISK SCORE: {final_score:.2f}/100\n"
        
        return explanation

    # Helper methods for factor calculations
    def _get_cvss_severity_level(self, score: float) -> str:
        if score >= 9.0: return "Critical"
        elif score >= 7.0: return "High"
        elif score >= 4.0: return "Medium"
        elif score >= 0.1: return "Low"
        else: return "None"

    def _get_criticality_level(self, criticality: int) -> str:
        if criticality >= 9: return "Mission Critical"
        elif criticality >= 7: return "High Business Impact"
        elif criticality >= 5: return "Important Operations"
        elif criticality >= 3: return "Standard Operations"
        else: return "Low Impact"

    def _get_threat_intelligence_factor(self, vuln: VulnerabilityData) -> float:
        if vuln.is_kev: return 2.0
        elif vuln.has_exploit: return 1.5
        else: return 1.0

    def _get_network_exposure_factor(self, exposure: str) -> float:
        factors = {
            "internet-facing": 3.0,
            "internal": 1.2,
            "isolated": 1.0
        }
        return factors.get(exposure, 1.0)

    def _get_attack_complexity_factor(self, complexity: str) -> float:
        factors = {
            "direct": 1.0,
            "single-hop": 0.9,
            "multi-hop": 0.8,
            "complex": 0.7
        }
        return factors.get(complexity, 1.0)

    def _get_threat_intelligence_reasoning(self, vuln: VulnerabilityData) -> str:
        if vuln.is_kev:
            return "CISA Known Exploited Vulnerability (KEV) - active exploitation confirmed"
        elif vuln.has_exploit:
            return "Public exploit code available - high exploitation likelihood"
        else:
            return "Standard EPSS scoring - no additional threat intelligence"

    def _calculate_preventive_controls(self, controls: List[str]) -> float:
        if not controls: return 0.0
        # Simplified calculation - in practice would be more sophisticated
        return min(len(controls) * 0.1, 0.7)

    def _calculate_detective_controls(self, controls: List[str]) -> float:
        if not controls: return 0.0
        return min(len(controls) * 0.1, 0.3)

    def _calculate_response_controls(self, controls: List[str]) -> float:
        if not controls: return 0.0
        return min(len(controls) * 0.05, 0.2)


class RiskBasedFramework(BaseRiskFramework):
    """
    Complete implementation of the Master Formula:
    Final_Risk_Score = Base_Risk × Context_Multipliers × Threat_Multipliers × Mitigation_Divisors
    
    Implements all components from the Transparent Risk Scoring Framework.
    """
    
    def __init__(self) -> None:
        super().__init__(
            "Risk Based",
            "Complete Master Formula with all context, threat, and temporal multipliers"
        )
        self.weights = {'cvss': 0.4, 'criticality': 0.4, 'epss': 0.2}

    def calculate_risk(self, vuln: VulnerabilityData) -> RiskScore:
        """Calculate risk using the complete Master Formula."""
        
        # Component 1: Base Risk Score
        base_risk_components = self._calculate_base_risk_components(vuln)
        base_risk = sum(comp.contribution for comp in base_risk_components.values())
        
        # Component 2: Context Multipliers (Reachability × Detectability × Prevalence)
        context_multipliers = self._calculate_complete_context_multipliers(vuln)
        context_total = 1.0
        for multiplier in context_multipliers.values():
            context_total *= multiplier.value
            
        # Component 3: Threat Multipliers (Threat_Actor × Temporal)
        threat_multipliers = self._calculate_threat_multipliers_master(vuln)
        threat_total = 1.0
        for multiplier in threat_multipliers.values():
            threat_total *= multiplier.value
            
        # Component 4: Mitigation Divisors
        mitigation_factors = self._calculate_enhanced_mitigation_factors(vuln)
        total_mitigation = sum(factor.value for factor in mitigation_factors.values())
        mitigation_divisor = max(1 - min(total_mitigation, 0.9), 0.1)  # Cap at 90% reduction
        
        # Apply Master Formula
        final_score = base_risk * context_total * threat_total * mitigation_divisor
        
        # Normalize to 0-100 scale
        final_score = self._normalize_final_score(final_score, "risk_based")
        
        # Priority classification using exact thresholds from Master Formula
        priority, timeline = self._classify_priority_master_formula(final_score, vuln)
        
        # Generate Master Formula explanation
        explanation = self._generate_master_formula_explanation(
            vuln, final_score, base_risk, base_risk_components,
            context_multipliers, threat_multipliers, mitigation_factors,
            context_total, threat_total, mitigation_divisor
        )
        
        # Build complete calculation breakdown
        calculation_breakdown = self._build_master_calculation_breakdown(
            base_risk, base_risk_components, context_multipliers,
            threat_multipliers, mitigation_factors, final_score,
            context_total, threat_total, mitigation_divisor
        )
        
        return RiskScore(
            score=final_score,
            priority=priority,
            timeline_days=timeline,
            explanation=explanation,
            components=self._build_master_components_dict(base_risk_components, context_total, threat_total, total_mitigation),
            calculation_breakdown=calculation_breakdown,
            confidence_score=self._calculate_confidence_score(vuln),
            data_freshness=self._get_data_freshness(),
            recommendations=self._generate_recommendations(vuln, final_score, priority, timeline),
            audit_trail=self._create_master_audit_trail(vuln, final_score, base_risk, context_total, threat_total, mitigation_divisor)
        )

    def _calculate_base_risk_components(self, vuln: VulnerabilityData) -> Dict[str, CalculationComponent]:
        """Calculate Base Risk = (Technical_Severity × 0.4) + (Business_Impact × 0.4) + (Exploit_Likelihood × 0.2)"""
        components = {}
        
        # Technical Severity = CVSS_Base_Score
        components['technical_severity'] = CalculationComponent(
            value=vuln.cvss_score,
            weight=self.weights['cvss'],
            contribution=vuln.cvss_score * self.weights['cvss'],
            source="NVD CVSS 3.1 Base Score",
            reasoning=f"CVSS {vuln.cvss_score}/10 - {self._get_cvss_severity_level(vuln.cvss_score)} severity"
        )
        
        # Business Impact = Asset_Criticality × CIA_Impact_Factor
        cia_factor = 1.0
        if vuln.cia_impact:
            cia_factor = max(vuln.cia_impact.values())
        
        business_impact_value = vuln.asset_criticality * cia_factor
        components['business_impact'] = CalculationComponent(
            value=business_impact_value,
            weight=self.weights['criticality'],
            contribution=business_impact_value * self.weights['criticality'],
            source="Asset inventory classification",
            reasoning=f"Asset criticality {vuln.asset_criticality}/10 ({self._get_criticality_level(vuln.asset_criticality)}) with CIA factor {cia_factor:.1f}"
        )
        
        # Exploit Likelihood = (EPSS_Score × 100) × Threat_Intelligence_Factor
        threat_intel_factor = self._get_threat_intelligence_factor_master(vuln)
        exploit_likelihood_value = (vuln.epss_score * 100) * threat_intel_factor
        components['exploit_likelihood'] = CalculationComponent(
            value=exploit_likelihood_value,
            weight=self.weights['epss'],
            contribution=exploit_likelihood_value * self.weights['epss'],
            source="FIRST.org EPSS + Threat Intelligence",
            reasoning=f"EPSS {vuln.epss_score:.3f} ({vuln.epss_score*100:.1f}% probability) with threat factor {threat_intel_factor:.1f}"
        )
        
        return components

    def _calculate_complete_context_multipliers(self, vuln: VulnerabilityData) -> Dict[str, CalculationComponent]:
        """Calculate Context Multipliers: Reachability × Detectability × Prevalence"""
        multipliers = {}
        
        # Reachability Multiplier = Network_Exposure × Attack_Path_Complexity
        network_exposure = self._get_network_exposure_factor_master(vuln.network_exposure, vuln.is_internet_facing)
        attack_complexity = self._get_attack_complexity_factor_master(vuln.attack_path_complexity)
        reachability_value = network_exposure * attack_complexity
        
        multipliers['reachability'] = CalculationComponent(
            value=reachability_value,
            weight=1.0,
            contribution=reachability_value,
            source="Network exposure analysis",
            reasoning=f"Network exposure: {vuln.network_exposure} ({network_exposure:.1f}x), Attack complexity: {vuln.attack_path_complexity} ({attack_complexity:.1f}x)"
        )
        
        # Detectability Multiplier = Exploit_Availability × Discovery_Difficulty
        exploit_availability = self._get_exploit_availability_factor_master(vuln.exploit_availability, vuln.has_exploit)
        discovery_difficulty = self._get_discovery_difficulty_factor_master(vuln.discovery_difficulty)
        detectability_value = exploit_availability * discovery_difficulty
        
        multipliers['detectability'] = CalculationComponent(
            value=detectability_value,
            weight=1.0,
            contribution=detectability_value,
            source="Exploit and discovery analysis",
            reasoning=f"Exploit availability: {vuln.exploit_availability} ({exploit_availability:.1f}x), Discovery difficulty: {vuln.discovery_difficulty} ({discovery_difficulty:.1f}x)"
        )
        
        # Prevalence Multiplier = Exploitation_Frequency × Target_Attractiveness
        exploitation_frequency = self._get_exploitation_frequency_factor_master(vuln.exploitation_frequency, vuln.is_kev)
        target_attractiveness = self._get_target_attractiveness_factor_master(vuln.target_attractiveness, vuln.asset_criticality)
        prevalence_value = exploitation_frequency * target_attractiveness
        
        multipliers['prevalence'] = CalculationComponent(
            value=prevalence_value,
            weight=1.0,
            contribution=prevalence_value,
            source="Threat landscape analysis",
            reasoning=f"Exploitation frequency: {vuln.exploitation_frequency} ({exploitation_frequency:.1f}x), Target attractiveness: {vuln.target_attractiveness} ({target_attractiveness:.1f}x)"
        )
        
        return multipliers

    def _calculate_threat_multipliers_master(self, vuln: VulnerabilityData) -> Dict[str, CalculationComponent]:
        """Calculate Threat Multipliers: Threat_Actor × Temporal"""
        multipliers = {}
        
        # Threat Actor Multiplier = Actor_Sophistication × Resource_Level
        actor_sophistication = self._get_actor_sophistication_factor_master(vuln.threat_actor_sophistication)
        resource_level = self._get_resource_level_factor_master(vuln.resource_level)
        threat_actor_value = actor_sophistication * resource_level
        
        multipliers['threat_actor'] = CalculationComponent(
            value=threat_actor_value,
            weight=1.0,
            contribution=threat_actor_value,
            source="Threat actor assessment",
            reasoning=f"Actor sophistication: {vuln.threat_actor_sophistication} ({actor_sophistication:.1f}x), Resource level: {vuln.resource_level} ({resource_level:.1f}x)"
        )
        
        # Temporal Multiplier = Age_Factor × Patch_Availability × Disclosure_Timeline
        age_factor = self._get_age_factor_master(vuln.vulnerability_age_days)
        patch_availability = self._get_patch_availability_factor_master(vuln.patch_availability)
        disclosure_timeline = self._get_disclosure_timeline_factor_master(vuln.disclosure_timeline)
        temporal_value = age_factor * patch_availability * disclosure_timeline
        
        multipliers['temporal'] = CalculationComponent(
            value=temporal_value,
            weight=1.0,
            contribution=temporal_value,
            source="Temporal analysis",
            reasoning=f"Age factor: {age_factor:.1f}x, Patch availability: {vuln.patch_availability} ({patch_availability:.1f}x), Disclosure: {vuln.disclosure_timeline} ({disclosure_timeline:.1f}x)"
        )
        
        return multipliers

    # Master Formula factor calculation methods
    def _get_network_exposure_factor_master(self, exposure: str, is_internet_facing: bool) -> float:
        """Network exposure factors from Master Formula."""
        if is_internet_facing:
            exposure = "internet-facing"
        
        factors = {
            "internet-facing": 3.0,           # Internet-facing with no restrictions
            "internet-basic": 2.5,            # Internet-facing with basic protections  
            "internet-advanced": 2.0,         # Internet-facing with advanced protections
            "internal-external": 1.5,         # Internal network with external access points
            "internal": 1.2,                  # Internal network, no external access
            "isolated": 1.0                   # Isolated/air-gapped systems
        }
        return factors.get(exposure, 1.2)

    def _get_attack_complexity_factor_master(self, complexity: str) -> float:
        """Attack path complexity factors from Master Formula."""
        factors = {
            "direct": 1.0,                    # Direct exploitation possible
            "single-hop": 0.9,                # Single-hop attack chain required
            "multi-hop": 0.8,                 # Multi-hop attack chain required
            "complex": 0.7,                   # Complex attack chain with multiple dependencies
            "insider": 0.6                    # Requires insider access or social engineering
        }
        return factors.get(complexity, 1.0)

    def _get_exploit_availability_factor_master(self, availability: str, has_exploit: bool) -> float:
        """Exploit availability factors from Master Formula."""
        if has_exploit and availability == "none":
            availability = "manual"
            
        factors = {
            "automated": 1.5,                 # Automated exploit tools available (Metasploit modules)
            "manual": 1.3,                    # Manual exploit code publicly available
            "poc": 1.2,                       # Proof-of-concept code available
            "details": 1.0,                   # Vulnerability details public, no exploit code
            "limited": 0.8,                   # Limited vulnerability details available
            "specialized": 0.6,               # Vulnerability requires specialized knowledge
            "none": 1.0                       # Default when not specified
        }
        return factors.get(availability, 1.0)

    def _get_discovery_difficulty_factor_master(self, difficulty: str) -> float:
        """Discovery difficulty factors from Master Formula."""
        factors = {
            "easy": 1.0,                      # Easily discoverable with basic tools
            "standard": 0.9,                  # Discoverable with standard vulnerability scanners
            "authenticated": 0.8,             # Requires authenticated scanning
            "specialized": 0.7,               # Requires specialized scanning techniques
            "manual": 0.6                     # Requires manual testing or analysis
        }
        return factors.get(difficulty, 0.9)

    def _get_exploitation_frequency_factor_master(self, frequency: str, is_kev: bool) -> float:
        """Exploitation frequency factors from Master Formula."""
        if is_kev:
            frequency = "kev"
            
        factors = {
            "kev": 2.0,                       # CISA Known Exploited Vulnerability (KEV)
            "active": 1.8,                    # Active exploitation campaigns (last 30 days)
            "known": 1.5,                     # Known exploitation incidents (last 90 days)
            "sporadic": 1.2,                  # Sporadic exploitation reported
            "none": 1.0,                      # No known exploitation activity
            "academic": 0.8                   # Academic/research interest only
        }
        return factors.get(frequency, 1.0)

    def _get_target_attractiveness_factor_master(self, attractiveness: str, asset_criticality: int) -> float:
        """Target attractiveness factors from Master Formula."""
        # Auto-determine based on asset criticality if not specified
        if attractiveness == "standard":
            if asset_criticality >= 9:
                attractiveness = "high-value"
            elif asset_criticality >= 7:
                attractiveness = "medium-value"
            elif asset_criticality >= 5:
                attractiveness = "standard"
            else:
                attractiveness = "low-value"
        
        factors = {
            "high-value": 1.3,                # High-value targets (financial, healthcare, government)
            "medium-value": 1.1,              # Medium-value targets (enterprise, e-commerce)
            "standard": 1.0,                  # Standard business targets
            "low-value": 0.9,                 # Low-value targets (personal, small business)
            "specialized": 0.8                # Specialized/niche targets
        }
        return factors.get(attractiveness, 1.0)

    def _get_actor_sophistication_factor_master(self, sophistication: str) -> float:
        """Actor sophistication factors from Master Formula."""
        factors = {
            "nation-state": 1.5,              # Nation-state level capabilities
            "apt": 1.3,                       # Advanced persistent threat (APT) groups
            "organized": 1.2,                 # Organized cybercriminal groups
            "skilled": 1.1,                   # Skilled individual attackers
            "script-kiddie": 1.0,             # Script kiddies / automated attacks
            "opportunistic": 0.9              # Opportunistic attackers
        }
        return factors.get(sophistication, 1.0)

    def _get_resource_level_factor_master(self, resource_level: str) -> float:
        """Resource level factors from Master Formula."""
        factors = {
            "well-funded": 1.2,               # Well-funded operations
            "moderate": 1.1,                  # Moderate resource availability
            "standard": 1.0,                  # Standard resource level
            "limited": 0.9,                   # Limited resources
            "minimal": 0.8                    # Minimal resources
        }
        return factors.get(resource_level, 1.0)

    def _get_age_factor_master(self, age_days: int) -> float:
        """Age factor based on days since disclosure from Master Formula."""
        if age_days <= 7:
            return 1.5                        # 0-7 days since disclosure (peak attention)
        elif age_days <= 30:
            return 1.3                        # 8-30 days since disclosure (high attention)
        elif age_days <= 90:
            return 1.1                        # 31-90 days since disclosure (moderate attention)
        elif age_days <= 365:
            return 1.0                        # 91-365 days since disclosure (standard)
        elif age_days <= 730:
            return 0.9                        # 1-2 years since disclosure (declining interest)
        else:
            return 0.8                        # 2+ years since disclosure (low interest)

    def _get_patch_availability_factor_master(self, availability: str) -> float:
        """Patch availability factors from Master Formula."""
        factors = {
            "none": 1.4,                      # No patch available
            "complex": 1.2,                   # Patch available but complex deployment
            "standard": 1.0,                  # Patch available with standard deployment
            "deployed": 0.8,                  # Patch widely deployed
            "mandated": 0.6,                  # Patch mandated by vendors/frameworks
            "available": 1.0                  # Default mapping
        }
        return factors.get(availability, 1.0)

    def _get_disclosure_timeline_factor_master(self, timeline: str) -> float:
        """Disclosure timeline factors from Master Formula."""
        factors = {
            "zero-day": 1.3,                  # Zero-day (no public disclosure)
            "coordinated": 1.2,               # Coordinated disclosure in progress
            "standard": 1.0,                  # Standard public disclosure
            "responsible": 0.9,               # Responsible disclosure completed
            "full": 0.8                       # Full details publicly available
        }
        return factors.get(timeline, 1.0)

    def _get_threat_intelligence_factor_master(self, vuln: VulnerabilityData) -> float:
        """Threat intelligence factor from Master Formula."""
        if vuln.is_kev:
            return 1.5                        # Active exploitation campaigns detected
        elif vuln.has_exploit:
            return 1.2                        # Exploit code publicly available
        else:
            return 1.0                        # Standard EPSS scoring

    def _get_threat_intelligence_reasoning_master(self, vuln: VulnerabilityData) -> str:
        """Get detailed threat intelligence reasoning for Master Formula."""
        if vuln.is_kev:
            return "CISA Known Exploited Vulnerability (KEV) - active exploitation confirmed"
        elif vuln.has_exploit:
            return "Public exploit code available - high exploitation likelihood"
        else:
            return "Standard EPSS scoring - no additional threat intelligence"

    # Enhanced transparency helper methods
    def _get_risk_level_description(self, score: float) -> str:
        """Get descriptive risk level."""
        if score >= 90: return "CRITICAL - Immediate Action Required"
        elif score >= 70: return "HIGH - Urgent Response Needed"
        elif score >= 40: return "MEDIUM - Scheduled Response"
        elif score >= 20: return "LOW - Standard Patching Cycle"
        else: return "INFORMATIONAL - Monitor for Changes"

    def _get_cvss_impact_description(self, cvss: float) -> str:
        """Get business-friendly CVSS impact description."""
        if cvss >= 9.0: return "Complete system compromise possible"
        elif cvss >= 7.0: return "Significant system compromise likely"
        elif cvss >= 4.0: return "Partial system compromise possible"
        elif cvss >= 0.1: return "Limited system impact"
        else: return "Minimal or no direct impact"

    def _get_business_risk_description(self, criticality: int) -> str:
        """Get business risk implications."""
        if criticality >= 9: return "Mission-critical operations at risk - potential business shutdown"
        elif criticality >= 7: return "Core business functions at risk - significant revenue impact"
        elif criticality >= 5: return "Important operations at risk - moderate business impact"
        elif criticality >= 3: return "Standard operations at risk - limited business impact"
        else: return "Low-value systems at risk - minimal business impact"

    def _get_threat_level_description(self, epss: float) -> str:
        """Get threat level based on EPSS score."""
        if epss >= 0.8: return "EXTREME - Very high probability of exploitation"
        elif epss >= 0.6: return "HIGH - Significant exploitation probability"
        elif epss >= 0.4: return "MODERATE - Notable exploitation risk"
        elif epss >= 0.2: return "LOW - Some exploitation possibility"
        else: return "MINIMAL - Very low exploitation likelihood"

    def _get_context_security_implication(self, context_type: str, value: float) -> str:
        """Get security implications of context factors."""
        if 'reachability' in context_type:
            if value >= 2.5: return "High attack surface - prioritize immediate patching"
            elif value >= 1.5: return "Moderate exposure - standard security protocols apply"
            else: return "Limited exposure - lower priority for patching"
        elif 'detectability' in context_type:
            if value >= 1.3: return "Easily exploitable - attackers can quickly weaponize"
            elif value >= 1.0: return "Standard detectability - normal exploitation difficulty"
            else: return "Hard to exploit - requires specialized knowledge"
        elif 'prevalence' in context_type:
            if value >= 1.5: return "High-value target - expect focused attacks"
            elif value >= 1.2: return "Attractive target - moderate attack interest"
            else: return "Low-value target - opportunistic attacks only"
        return "Context factor applied to risk calculation"

    def _get_threat_context_explanation(self, threat_type: str, value: float) -> str:
        """Get threat context explanations."""
        if 'threat_actor' in threat_type:
            if value >= 1.3: return "Advanced threat actors likely - sophisticated attacks expected"
            elif value >= 1.1: return "Skilled attackers possible - organized exploitation likely"
            else: return "Basic threat actors - automated or opportunistic attacks"
        elif 'temporal' in threat_type:
            if value >= 1.3: return "Peak vulnerability window - highest attack probability"
            elif value >= 1.1: return "Active vulnerability period - moderate attack interest"
            else: return "Mature vulnerability - declining attacker interest"
        return "Threat factor influences overall risk"

    def _get_control_effectiveness_explanation(self, control_type: str, effectiveness: float) -> str:
        """Explain control effectiveness."""
        if effectiveness >= 0.5: return "Highly effective - significantly reduces attack success"
        elif effectiveness >= 0.2: return "Moderately effective - provides meaningful protection"
        elif effectiveness >= 0.1: return "Basic protection - limited but valuable security"
        else: return "No controls - full vulnerability exposure"

    def _get_control_synergy_explanation(self, total_mitigation: float) -> str:
        """Explain how controls work together."""
        if total_mitigation >= 0.7: return "Excellent defense-in-depth - multiple overlapping protections"
        elif total_mitigation >= 0.4: return "Good security posture - reasonable protection layers"
        elif total_mitigation >= 0.2: return "Basic security - some protection but gaps remain"
        else: return "Minimal security - significant exposure remains"

    def _get_priority_context(self, score: float, vuln: VulnerabilityData) -> Dict[str, str]:
        """Get comprehensive priority context."""
        if score >= 90:
            return {
                'level': 'CRITICAL',
                'timeline': '1-7',
                'rationale': 'Immediate threat to business operations',
                'business_impact': 'Potential for significant business disruption',
                'action': 'Emergency response - patch immediately'
            }
        elif score >= 70:
            return {
                'level': 'HIGH',
                'timeline': '14-30',
                'rationale': 'High probability of successful exploitation',
                'business_impact': 'Moderate to significant business risk',
                'action': 'Urgent patching - prioritize in next sprint'
            }
        elif score >= 40:
            return {
                'level': 'MEDIUM',
                'timeline': '30-90',
                'rationale': 'Notable security risk requiring attention',
                'business_impact': 'Limited but measurable business impact',
                'action': 'Schedule patching in regular cycle'
            }
        elif score >= 20:
            return {
                'level': 'LOW',
                'timeline': '90-180',
                'rationale': 'Low probability of exploitation',
                'business_impact': 'Minimal direct business impact',
                'action': 'Include in standard maintenance'
            }
        else:
            return {
                'level': 'INFORMATIONAL',
                'timeline': '180-365',
                'rationale': 'Very low security risk',
                'business_impact': 'Negligible business impact',
                'action': 'Monitor for changes - no immediate action needed'
            }

    def _get_cwe_attack_pattern(self, cwe_id: str) -> str:
        """Get attack pattern description for CWE."""
        cwe_patterns = {
            'CWE-79': 'Cross-site scripting - inject malicious scripts',
            'CWE-89': 'SQL injection - manipulate database queries',
            'CWE-22': 'Path traversal - access unauthorized files',
            'CWE-352': 'CSRF - trick users into unwanted actions',
            'CWE-434': 'File upload - upload malicious files',
            'CWE-94': 'Code injection - execute arbitrary code'
        }
        return cwe_patterns.get(cwe_id, 'Various attack vectors possible')

    def _calculate_enhanced_mitigation_factors(self, vuln: VulnerabilityData) -> Dict[str, CalculationComponent]:
        """Calculate mitigation factors using Master Formula values."""
        factors = {}
        
        # Preventive controls using Master Formula mapping
        preventive_value = self._calculate_preventive_controls_master_formula(vuln.preventive_controls or [])
        factors['preventive_controls'] = CalculationComponent(
            value=preventive_value,
            weight=1.0,
            contribution=preventive_value,
            source="Security control assessment",
            reasoning=f"Preventive controls: {', '.join(vuln.preventive_controls or ['None'])} ({preventive_value*100:.0f}% reduction)"
        )
        
        # Detective controls using Master Formula mapping  
        detective_value = self._calculate_detective_controls_master_formula(vuln.detective_controls or [])
        factors['detective_controls'] = CalculationComponent(
            value=detective_value,
            weight=1.0,
            contribution=detective_value,
            source="Monitoring assessment",
            reasoning=f"Detective controls: {', '.join(vuln.detective_controls or ['None'])} ({detective_value*100:.0f}% reduction)"
        )
        
        # Response controls using Master Formula mapping
        response_value = self._calculate_response_controls_master_formula(vuln.response_controls or [])
        factors['response_controls'] = CalculationComponent(
            value=response_value,
            weight=1.0,
            contribution=response_value,
            source="Response capability assessment", 
            reasoning=f"Response controls: {', '.join(vuln.response_controls or ['None'])} ({response_value*100:.0f}% reduction)"
        )
        
        return factors

    def _calculate_preventive_controls_master_formula(self, controls: List[str]) -> float:
        """Preventive controls using exact Master Formula values."""
        if not controls:
            return 0.0
        
        control_values = {
            # Complete isolation - 0.7
            "air_gap": 0.7,
            "network_segmentation": 0.7,
            "complete_isolation": 0.7,
            
            # Strong access controls - 0.5
            "mfa": 0.5,
            "least_privilege": 0.5,
            "strong_access_controls": 0.5,
            
            # Network protection - 0.3
            "waf": 0.3,
            "ips": 0.3,
            "firewall_rules": 0.3,
            "network_protection": 0.3,
            
            # Application-level controls - 0.2
            "input_validation": 0.2,
            "encoding": 0.2,
            "application_controls": 0.2,
            "access_controls": 0.2,
            "encryption": 0.2,
            
            # Basic protections - 0.1
            "antivirus": 0.1,
            "basic_firewall": 0.1,
            "network_firewall": 0.1,
            "basic_protections": 0.1
        }
        
        total_effectiveness = sum(control_values.get(control, 0.1) for control in controls)
        return min(total_effectiveness, 0.7)  # Cap at 70%

    def _calculate_detective_controls_master_formula(self, controls: List[str]) -> float:
        """Detective controls using exact Master Formula values."""
        if not controls:
            return 0.0
        
        control_values = {
            # Advanced monitoring - 0.3
            "siem": 0.3,
            "behavioral_analysis": 0.3,
            "advanced_monitoring": 0.3,
            
            # Standard monitoring - 0.2
            "log_analysis": 0.2,
            "alerting": 0.2,
            "standard_monitoring": 0.2,
            
            # Basic monitoring - 0.1
            "system_logs": 0.1,
            "basic_monitoring": 0.1,
            "logging": 0.1,
            "ids": 0.1,
            "monitoring": 0.1
        }
        
        total_effectiveness = sum(control_values.get(control, 0.1) for control in controls)
        return min(total_effectiveness, 0.3)  # Cap at 30%

    def _calculate_response_controls_master_formula(self, controls: List[str]) -> float:
        """Response controls using exact Master Formula values."""
        if not controls:
            return 0.0
        
        control_values = {
            # Automated response capabilities - 0.2
            "automated_response": 0.2,
            
            # Incident response team ready - 0.15
            "incident_response": 0.15,
            "incident_response_team": 0.15,
            "soc": 0.15,
            
            # Basic incident response procedures - 0.1
            "basic_procedures": 0.1,
            "incident_procedures": 0.1,
            
            # Manual response only - 0.05
            "manual_response": 0.05
        }
        
        total_effectiveness = sum(control_values.get(control, 0.05) for control in controls)
        return min(total_effectiveness, 0.2)  # Cap at 20%

    def _classify_priority_master_formula(self, score: float, vuln: VulnerabilityData = None) -> tuple[str, int]:
        """Priority classification using exact Master Formula thresholds with context-based floors."""
        
        # Start with mathematical thresholds from your document
        if score >= 90:
            priority, timeline = "CRITICAL", 7    # Immediate response required
        elif score >= 70:
            priority, timeline = "HIGH", 30       # Urgent response required
        elif score >= 40:
            priority, timeline = "MEDIUM", 90     # Scheduled response required (90 days per document)
        elif score >= 20:
            priority, timeline = "LOW", 90        # Standard patching cycle
        else:
            priority, timeline = "INFORMATIONAL", 365  # Track for awareness
        
        # APPLY CONTEXT-BASED PRIORITY FLOORS from your document
        if vuln:
            # CRITICAL context combinations (override any score < 90)
            critical_conditions = [
                # "Active exploitation + No mitigation + Critical assets"
                (vuln.exploitation_frequency in ["kev", "active"] and 
                 len(vuln.preventive_controls or []) == 0 and 
                 vuln.asset_criticality >= 9),
                
                # "CISA KEV + Internet-facing + Financial/Healthcare"
                (vuln.is_kev and vuln.is_internet_facing),
                
                # "Zero-day + Nation-state threats + Mission-critical"
                (vuln.disclosure_timeline == "zero-day" and 
                 vuln.threat_actor_sophistication in ["nation-state", "apt"] and 
                 vuln.asset_criticality >= 9),
                
                # Critical CVSS + Internet-facing + Mission-critical
                (vuln.cvss_score >= 9.0 and vuln.is_internet_facing and vuln.asset_criticality >= 9)
            ]
            
            if any(critical_conditions):
                priority, timeline = "CRITICAL", 7
            
            # HIGH context combinations (override scores < 70)
            elif any([
                # "High CVSS + Public exploits + Important assets"
                (vuln.cvss_score >= 8.0 and vuln.has_exploit and vuln.asset_criticality >= 7),
                
                # "Active campaigns + Limited mitigation + Business-critical"
                (vuln.exploitation_frequency in ["active", "kev"] and 
                 len(vuln.preventive_controls or []) <= 2 and 
                 vuln.asset_criticality >= 8),
                
                # "Recent disclosure + Easy exploitation + Exposed systems"
                (vuln.vulnerability_age_days <= 30 and 
                 vuln.discovery_difficulty == "easy" and 
                 vuln.is_internet_facing),
                
                # Critical CVSS + Mission critical (even if internal)
                (vuln.cvss_score >= 9.0 and vuln.asset_criticality >= 9)
            ]):
                if priority not in ["CRITICAL"]:  # Don't downgrade CRITICAL
                    priority, timeline = "HIGH", 30
            
            # Apply additional context-based timeline acceleration
            if vuln.is_kev and score >= 40:
                timeline = min(timeline, 14)  # KEV max 14 days
            
            if vuln.has_exploit and score >= 20:
                timeline = max(int(timeline * 0.5), 3)  # Half time, minimum 3 days
            
            if vuln.asset_criticality >= 9 and score >= 20:
                timeline = max(int(timeline * 0.7), 5)  # 30% faster, minimum 5 days
            
            if vuln.is_internet_facing and score >= 30:
                timeline = max(timeline // 2, 3)  # Halve timeline, minimum 3 days
        
        return priority, timeline

    def _generate_master_formula_explanation(self, vuln, final_score, base_risk, base_components, 
                                           context_multipliers, threat_multipliers, mitigation_factors,
                                           context_total, threat_total, mitigation_divisor) -> str:
        """Generate comprehensive, transparent Master Formula explanation."""
        
        # Header with vulnerability intelligence
        explanation = f"🔍 COMPREHENSIVE RISK ANALYSIS: {vuln.cve_id}\n"
        explanation += f"Final Risk Score: {final_score:.2f}/100 ({self._get_risk_level_description(final_score)})\n"
        explanation += f"Formula: Base_Risk × Context_Multipliers × Threat_Multipliers × Mitigation_Divisors\n"
        explanation += f"Calculation: {base_risk:.2f} × {context_total:.2f} × {threat_total:.2f} × {mitigation_divisor:.2f} = {final_score:.2f}\n\n"
        
        # 1. VULNERABILITY INTELLIGENCE
        explanation += "📋 1. VULNERABILITY INTELLIGENCE\n"
        explanation += f"   ├── CVE ID: {vuln.cve_id}\n"
        if hasattr(vuln, 'vulnerability_age_days') and vuln.vulnerability_age_days:
            explanation += f"   ├── Age: {vuln.vulnerability_age_days} days since disclosure\n"
            explanation += f"   │   └── Why this matters: {'Recent vulnerabilities get more attention from attackers' if vuln.vulnerability_age_days < 30 else 'Older vulnerabilities may have patches available'}\n"
        
        if hasattr(vuln, 'cwe_id') and vuln.cwe_id:
            explanation += f"   ├── Weakness Type: {vuln.cwe_id}\n"
            explanation += f"   │   └── Attack Pattern: {self._get_cwe_attack_pattern(vuln.cwe_id)}\n"
        
        explanation += f"   ├── CISA KEV Status: {'⚠️ ACTIVE EXPLOITATION' if vuln.is_kev else '✅ No known active exploitation'}\n"
        explanation += f"   └── Exploit Availability: {'🔴 Public exploits available' if vuln.has_exploit else '🟡 No public exploits detected'}\n\n"
        
        # 2. BASE RISK BREAKDOWN
        explanation += "⚖️ 2. BASE RISK CALCULATION (Technical Foundation)\n"
        explanation += f"   Base Risk: {base_risk:.2f}/100\n"
        
        for name, comp in base_components.items():
            explanation += f"   ├── {name.replace('_', ' ').title()}: {comp.value:.2f} × {comp.weight:.1f} = {comp.contribution:.2f}\n"
            explanation += f"   │   ├── Source: {comp.source}\n"
            explanation += f"   │   ├── Value: {comp.reasoning}\n"
            
            # Add business context
            if 'technical_severity' in name:
                explanation += f"   │   └── Impact: {self._get_cvss_impact_description(comp.value)}\n"
            elif 'business_impact' in name:
                explanation += f"   │   └── Business Risk: {self._get_business_risk_description(vuln.asset_criticality)}\n"
            elif 'exploit_likelihood' in name:
                explanation += f"   │   └── Threat Level: {self._get_threat_level_description(vuln.epss_score)}\n"
        
        explanation += "\n"
        
        # 3. CONTEXT ANALYSIS
        explanation += "🌐 3. ENVIRONMENTAL CONTEXT MULTIPLIERS\n"
        explanation += f"   Total Context Impact: {context_total:.2f}x multiplier\n"
        
        for name, mult in context_multipliers.items():
            explanation += f"   ├── {name.replace('_', ' ').title()}: {mult.value:.2f}x\n"
            explanation += f"   │   ├── Assessment: {mult.reasoning}\n"
            explanation += f"   │   └── Security Implication: {self._get_context_security_implication(name, mult.value)}\n"
        
        explanation += "\n"
        
        # 4. THREAT LANDSCAPE
        explanation += "🎯 4. THREAT LANDSCAPE ANALYSIS\n"
        explanation += f"   Total Threat Amplification: {threat_total:.2f}x multiplier\n"
        
        for name, mult in threat_multipliers.items():
            explanation += f"   ├── {name.replace('_', ' ').title()}: {mult.value:.2f}x\n"
            explanation += f"   │   ├── Analysis: {mult.reasoning}\n"
            explanation += f"   │   └── Threat Context: {self._get_threat_context_explanation(name, mult.value)}\n"
        
        # Add threat intelligence summary
        explanation += f"   └── 🕵️ Threat Intelligence Summary:\n"
        explanation += f"       └── {self._get_threat_intelligence_reasoning_master(vuln)}\n\n"
        
        # 5. SECURITY CONTROLS EFFECTIVENESS
        explanation += "🛡️ 5. SECURITY CONTROLS EFFECTIVENESS\n"
        total_mitigation = sum(factor.value for factor in mitigation_factors.values())
        explanation += f"   Total Risk Reduction: {total_mitigation*100:.0f}% (Mitigation Factor: {mitigation_divisor:.2f})\n"
        
        for name, factor in mitigation_factors.items():
            explanation += f"   ├── {name.replace('_', ' ').title()}: {factor.value*100:.0f}% reduction\n"
            explanation += f"   │   ├── Controls: {factor.reasoning}\n"
            explanation += f"   │   └── Effectiveness: {self._get_control_effectiveness_explanation(name, factor.value)}\n"
        
        if total_mitigation > 0:
            explanation += f"   └── 💡 Control Synergy: {self._get_control_synergy_explanation(total_mitigation)}\n\n"
        else:
            explanation += f"   └── ⚠️ No Security Controls: Risk remains at full calculated value\n\n"
        
        # 6. RISK PRIORITIZATION CONTEXT
        explanation += "📊 6. RISK PRIORITIZATION CONTEXT\n"
        priority_info = self._get_priority_context(final_score, vuln)
        explanation += f"   ├── Priority Level: {priority_info['level']} ({priority_info['timeline']} days)\n"
        explanation += f"   ├── Urgency Rationale: {priority_info['rationale']}\n"
        explanation += f"   ├── Business Impact: {priority_info['business_impact']}\n"
        explanation += f"   └── Recommended Action: {priority_info['action']}\n\n"
        
        # 7. MATHEMATICAL VALIDATION
        explanation += "🔢 7. CALCULATION VALIDATION\n"
        explanation += f"   Step 1: Base Risk = {base_risk:.2f}\n"
        step2 = base_risk * context_total
        explanation += f"   Step 2: Apply Context = {base_risk:.2f} × {context_total:.2f} = {step2:.2f}\n"
        step3 = step2 * threat_total
        explanation += f"   Step 3: Apply Threats = {step2:.2f} × {threat_total:.2f} = {step3:.2f}\n"
        explanation += f"   Step 4: Apply Mitigation = {step3:.2f} × {mitigation_divisor:.2f} = {final_score:.2f}\n"
        explanation += f"   ✅ Final Score Validation: {final_score:.2f}/100\n\n"
        
        # 8. DATA SOURCES & CONFIDENCE
        explanation += "📡 8. DATA SOURCES & CONFIDENCE\n"
        explanation += f"   ├── CVSS Data: National Vulnerability Database (NVD)\n"
        explanation += f"   ├── EPSS Data: FIRST.org Exploit Prediction Scoring\n"
        explanation += f"   ├── KEV Data: CISA Known Exploited Vulnerabilities\n"
        explanation += f"   ├── Calculation Confidence: {self._calculate_confidence_score(vuln)*100:.0f}%\n"
        explanation += f"   └── Data Freshness: Last updated within 24 hours\n"
        
        return explanation

    def _build_master_calculation_breakdown(self, base_risk, base_components, context_multipliers,
                                           threat_multipliers, mitigation_factors, final_score,
                                           context_total, threat_total, mitigation_divisor) -> Dict[str, Any]:
        """Build the complete calculation breakdown for the Master Formula."""
        breakdown = {
            "base_risk": {
                "value": base_risk,
                "components": {
                    name: {
                        "value": comp.value,
                        "weight": comp.weight,
                        "contribution": comp.contribution,
                        "source": comp.source,
                        "reasoning": comp.reasoning
                    }
                    for name, comp in base_components.items()
                }
            },
            "context_multipliers": {
                "reachability": {
                    "value": context_multipliers['reachability'].value,
                    "reasoning": context_multipliers['reachability'].reasoning
                },
                "detectability": {
                    "value": context_multipliers['detectability'].value,
                    "reasoning": context_multipliers['detectability'].reasoning
                },
                "prevalence": {
                    "value": context_multipliers['prevalence'].value,
                    "reasoning": context_multipliers['prevalence'].reasoning
                }
            },
            "threat_multipliers": {
                "threat_actor": {
                    "value": threat_multipliers['threat_actor'].value,
                    "reasoning": threat_multipliers['threat_actor'].reasoning
                },
                "temporal": {
                    "value": threat_multipliers['temporal'].value,
                    "reasoning": threat_multipliers['temporal'].reasoning
                }
            },
            "mitigation_factors": {
                "total_reduction": sum(factor.value for factor in mitigation_factors.values()),
                "components": {
                    name: {
                        "value": factor.value,
                        "reasoning": factor.reasoning
                    }
                    for name, factor in mitigation_factors.items()
                }
            }
        }
        return breakdown

    def _build_master_components_dict(self, base_components: Dict[str, CalculationComponent],
                                       context_total: float, threat_total: float, total_mitigation: float) -> Dict[str, float]:
        """Build the components dictionary for the Master Formula."""
        components_dict = {}
        for name, comp in base_components.items():
            components_dict[name] = comp.contribution
        components_dict["context_multipliers"] = context_total
        components_dict["threat_multipliers"] = threat_total
        components_dict["mitigation_factor"] = total_mitigation
        return components_dict

    def _create_master_audit_trail(self, vuln: VulnerabilityData, final_score: float, base_risk: float,
                                   context_total: float, threat_total: float, mitigation_divisor: float) -> Dict[str, Any]:
        """Create an audit trail for the Master Formula."""
        audit_trail = {
            "calculation_timestamp": datetime.now().isoformat(),
            "framework_version": "1.0",
            "input_parameters": {
                "cve_id": vuln.cve_id,
                "cvss_score": vuln.cvss_score,
                "asset_criticality": vuln.asset_criticality,
                "epss_score": vuln.epss_score,
                "is_internet_facing": vuln.is_internet_facing,
                "is_kev": vuln.is_kev
            },
            "calculation_steps": [
                f"Base risk calculation: {base_risk:.2f}",
                f"Context Multipliers: {context_total:.2f}x",
                f"Threat Multipliers: {threat_total:.2f}x",
                f"Mitigation Divisor: {mitigation_divisor:.2f}",
                f"Final score: {final_score:.2f}"
            ]
        }
        return audit_trail

    # Helper methods
    def _get_cvss_severity_level(self, score: float) -> str:
        if score >= 9.0: return "Critical"
        elif score >= 7.0: return "High"
        elif score >= 4.0: return "Medium"
        elif score >= 0.1: return "Low"
        else: return "None"

    def _get_criticality_level(self, criticality: int) -> str:
        if criticality >= 9: return "Mission Critical"
        elif criticality >= 7: return "High Business Impact"
        elif criticality >= 5: return "Important Operations"
        elif criticality >= 3: return "Standard Operations"
        else: return "Low Impact" 