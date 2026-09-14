import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './card';
import { Badge } from './badge';
import { Button } from './button';

interface FrameworkGuideProps {
  selectedFramework: string;
  onFrameworkChange: (framework: string) => void;
}

export const FrameworkGuide: React.FC<FrameworkGuideProps> = ({ 
  selectedFramework, 
  onFrameworkChange 
}) => {
  const [showDetails, setShowDetails] = useState(false);

  const frameworks = [
    {
      id: "enhanced",
      name: "Enhanced Contextual",
      shortDesc: "Fast, business-aligned risk scoring with real vulnerability data",
      formula: "Base_Risk × Reachability_Multiplier × (1 - Mitigation_Factor)",
      factors: "Live NVD/EPSS",
      speed: "Fast",
      accuracy: "85%",
      idealFor: "SaaS, E-commerce, Agile teams",
      mathDetails: {
        components: [
          "Base Risk = (CVSS × 0.4) + (Asset_Criticality × 0.4) + (EPSS × 100 × 0.2)",
          "Reachability = Network_Exposure × Attack_Path_Complexity (from real CVSS vector)",
          "Network_Exposure: Internet-facing (3.0x), Internal (1.2x), Isolated (1.0x)",
          "Attack_Path_Complexity: Direct (1.0x), Multi-hop (0.8x), Complex (0.7x)",
          "Mitigation = Preventive + Detective + Response Controls",
          "Data Sources = Live NVD API, FIRST.org EPSS, CISA KEV catalog"
        ],
        benefits: [
          "Fast assessment for agile environments",
          "Business impact prioritization", 
          "Real vulnerability data integration",
          "Clear asset-risk correlation"
        ]
      },
      color: "bg-blue-100 text-blue-800 border-blue-200"
    },
    {
      id: "mitigation-contextual",
      name: "Mitigation Contextual", 
      shortDesc: "CVE-aware security controls with intelligent context determination",
      formula: "Base_Risk × Reachability_Multiplier × (1 - Mitigation_Factor)",
      factors: "Real CVE data",
      speed: "Standard",
      accuracy: "90%",
      idealFor: "Security teams, Compliance, MSPs",
      mathDetails: {
        components: [
          "Base Risk = (CVSS × 0.4) + (Asset_Criticality × 0.4) + (EPSS × 100 × 0.2)",
          "Reachability = Network_Exposure × Attack_Path_Complexity (from real CVSS vector)",
          "Mitigation = User-specified controls with intelligent context (up to 90% reduction)",
          "Intelligence = Real CVE age, CISA KEV status, exploit references, threat factors",
          "Dynamic context determination from NVD/EPSS APIs",
          "Exploit detection from CVE reference analysis"
        ],
        benefits: [
          "Real vulnerability data integration",
          "Intelligent context determination", 
          "CISA KEV catalog integration",
          "Exploit reference detection"
        ]
      },
      color: "bg-green-100 text-green-800 border-green-200"
    },
    {
      id: "risk-based",
      name: "Risk Based",
      shortDesc: "Complete Master Formula with all context, threat, and temporal multipliers", 
      formula: "Base_Risk × Context_Multipliers × Threat_Multipliers × Mitigation_Divisors",
      factors: "15+ real factors",
      speed: "Comprehensive",
      accuracy: "95%+",
      idealFor: "Fortune 500, Government, Regulated industries",
      mathDetails: {
        components: [
          "Base_Risk = (Technical_Severity × 0.4) + (Business_Impact × 0.4) + (Exploit_Likelihood × 0.2)",
          "Context_Multipliers = Reachability × Detectability × Prevalence (from real CVE/EPSS data)",
          "Threat_Multipliers = Threat_Actor × Temporal (CISA KEV, age, patch status)",
          "Reachability = Network_Exposure × Attack_Path_Complexity (0.6-3.0x)",
          "Detectability = Exploit_Availability × Discovery_Difficulty (0.36-1.5x)",
          "Prevalence = Exploitation_Frequency × Target_Attractiveness (0.64-2.6x)",
          "Threat_Actor = Actor_Sophistication × Resource_Level (0.72-1.8x)",
          "Temporal = Age_Factor × Patch_Availability × Disclosure_Timeline (0.48-2.73x)",
          "Intelligence = Real NVD publication dates, CISA KEV catalog, EPSS percentiles, exploit detection",
          "Context-based priority floors prevent inappropriate risk downgrades"
        ],
        benefits: [
          "Real vulnerability data integration",
          "Complete threat intelligence integration",
          "Context-based priority floors",
          "Regulatory audit ready",
          "CISA KEV catalog integration"
        ]
      },
      color: "bg-purple-100 text-purple-800 border-purple-200"
    },
    {
      id: "fedramp-vdr",
      name: "FedRAMP VDR Standard",
      shortDesc: "N1-N5 federal impact classification, LEV/IRV assessment, and exact timeline enforcement per VDR Standard",
      formula: "Federal_Impact_Classification + LEV_Assessment + IRV_Assessment + Timeline_Classification",
      factors: "Federal compliance factors",
      speed: "Compliance-focused",
      accuracy: "100% FedRAMP compliant",
      idealFor: "Federal agencies, FedRAMP authorized systems, Government contractors",
      mathDetails: {
        components: [
          "Impact Rating = N1-N5 classification per FRD-ALL-32 through FRD-ALL-35",
          "LEV Assessment = Likely Exploitable Vulnerability per FRD-ALL-23 (3-condition validation)",
          "IRV Assessment = Internet-Reachable Vulnerability per FRD-ALL-24 (payload-triggered scenarios)",
          "Timeline Classification = LEV+IRV (3 days), LEV+NIRV (7 days), NLEV (21 days)",
          "Context Factors = Mission criticality, reachability, exploitability, detectability, prevalence",
          "Compliance Status = Incident response requirements, federal notification triggers",
          "Federal Data Fields = Service degradation, federal data exposure, downtime, affected users",
          "Machine-readable reporting per FRR-VDR-RP-05 requirements"
        ],
        benefits: [
          "100% FedRAMP VDR Standard compliant",
          "N1-N5 federal impact classification",
          "LEV/IRV assessment engines",
          "Exact timeline enforcement",
          "Federal notification automation",
          "Compliance audit ready"
        ]
      },
      color: "bg-red-100 text-red-800 border-red-200"
    }
  ];

  const selectedFrameworkData = frameworks.find(f => f.id === selectedFramework);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <label className="block text-sm font-medium">Risk Assessment Framework</label>
        <Button 
          variant="outline" 
          size="sm"
          onClick={() => setShowDetails(!showDetails)}
        >
          {showDetails ? 'Hide' : 'Show'} Formula Details
        </Button>
      </div>

      {/* Framework Selector - Compact Dropdown Style */}
      <div className="space-y-2">
        <select
          value={selectedFramework}
          onChange={(e) => onFrameworkChange(e.target.value)}
          className="w-full p-3 border border-gray-300 rounded-lg bg-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          aria-label="Select Risk Assessment Framework"
        >
          {frameworks.map((framework) => (
            <option key={framework.id} value={framework.id}>
              {framework.name} - {framework.shortDesc}
            </option>
          ))}
        </select>
        
        {/* Selected Framework Summary */}
        {selectedFrameworkData && (
          <div className="bg-gray-50 p-3 rounded-lg border">
            <div className="mb-2">
              <span className="font-medium text-gray-900">{selectedFrameworkData.name}</span>
            </div>
            <p className="text-sm text-gray-600 mb-2">{selectedFrameworkData.shortDesc}</p>
            <p className="text-xs font-mono bg-white p-2 rounded border">
              {selectedFrameworkData.formula}
            </p>
          </div>
        )}
      </div>

      {/* Detailed Mathematical Breakdown */}
      {showDetails && selectedFrameworkData && (
        <Card>
          <CardHeader>
            <CardTitle>
              {selectedFrameworkData.name} - Mathematical Details
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="bg-gray-50 p-3 rounded-lg">
                <h5 className="font-medium mb-1">Complete Formula:</h5>
                <p className="font-mono text-sm">{selectedFrameworkData.formula}</p>
              </div>

              <div>
                <h5 className="font-medium mb-2">Mathematical Components:</h5>
                <ul className="space-y-1">
                  {selectedFrameworkData.mathDetails.components.map((component, index) => (
                    <li key={index} className="text-sm flex items-start">
                      <span className="w-2 h-2 bg-blue-500 rounded-full mr-2 mt-2 flex-shrink-0"></span>
                      <span className="font-mono text-xs">{component}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
