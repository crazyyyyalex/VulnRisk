import React, { useState } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Slider } from './ui/slider';
import { Badge } from './ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { FrameworkSelector } from './FrameworkSelector';
import { API_ENDPOINTS } from '../config/api';
import { Shield, TrendingUp, AlertTriangle, Lightbulb, BarChart3, Clock, Download } from 'lucide-react';

interface RiskScoreResponse {
  cve_id: string;
  risk_score: number;
  priority: string;
  timeline_days: number;
  explanation: string;
  components: Record<string, number>;
  calculation_breakdown: any;
  confidence_score: number;
  data_freshness: Record<string, string>;
  recommendations: string[];
  audit_trail: any;
}

interface VDRResponse {
  cve_id: string;
  impact_rating: string;
  lev: {
    status: boolean;
    reasons: string[];
  };
  irv: {
    status: boolean;
    reasons: string[];
    payload_contexts: string[];
  };
  timeline: {
    category: string;
    days: number;
  };
  context_factors: Record<string, any>;
  incident_response_required: boolean;
  compliance_report: Record<string, any>;
  federal_impact_fields: {
    service_degradation_hours?: number;
    federal_data_exposure_percentage?: number;
    estimated_downtime_hours?: number;
    affected_users_percentage?: number;
  };
  incident_response: {
    required: boolean;
    incident_id: string | null;
    severity: string | null;
    federal_notification_required: boolean;
    escalation_required: boolean;
  };
  remediation_timeline: {
    timeline_days: number;
    status: string;
    days_remaining: number;
    escalation_required: boolean;
    responsible_team: string;
    mitigation_actions: string[];
  };
  authorization_level: string;
  assessment_timestamp: string | null;
  framework_version: string;
}

export const RiskCalculator: React.FC = () => {
  const { isAuthenticated, loginWithRedirect, getAccessTokenSilently } = useAuth0();
  const [cveId, setCveId] = useState('');
  const [assetCriticality, setAssetCriticality] = useState(5);
  const [isInternetFacing, setIsInternetFacing] = useState(false);
  const [selectedFramework, setSelectedFramework] = useState('enhanced');
  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);
  const [vdrResult, setVdrResult] = useState<VDRResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview');

  const calculateRisk = async () => {
    setError(null);
    setRiskScore(null);
    setVdrResult(null);
    
    try {
      // Prepare headers - include auth token if available
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      
      if (isAuthenticated) {
        try {
          const token = await getAccessTokenSilently();
          headers['Authorization'] = `Bearer ${token}`;
        } catch (authError) {
          console.warn('Could not get auth token, proceeding without authentication');
        }
      }
      
      // Handle VDR framework separately
      if (selectedFramework === 'fedramp-vdr') {
        // First fetch CVE intelligence data to get KEV status
        const scoreResponse = await fetch(API_ENDPOINTS.score(), {
          method: 'POST',
          headers,
          body: JSON.stringify({
            cve_id: cveId,
            asset_criticality: assetCriticality,
            is_internet_facing: isInternetFacing,
            framework: 'enhanced'
          })
        });
        
        let cveIntel = { epss: 0.0, kev: false };
        if (scoreResponse.ok) {
          const scoreData = await scoreResponse.json();
          cveIntel = {
            epss: scoreData.cve_intelligence?.epss_score || 0.0,
            kev: scoreData.cve_intelligence?.cisa_kev || false
          };
        }
        
        const response = await fetch(API_ENDPOINTS.fedrampVDRAssess(), {
          method: 'POST',
          headers,
          body: JSON.stringify({
            cve_id: cveId,
            internet_reachable: isInternetFacing,
            mission_criticality: assetCriticality,
            mitigation_effectiveness: 0.0,
            epss: cveIntel.epss,
            reachability_paths: isInternetFacing ? ['unauthenticated_http'] : [],
            vulnerability_discovery_ease: 0.5,
            exploitation_likelihood: 0.3,
            inventory_impact_pct: 10.0,
            granted_privilege_level: 'user',
            vulnerability_chaining_indicators: [],
            threat_intel_tags: cveIntel.kev ? ["cisa_kev"] : [],
            service_degradation_hours: 0.0,
            federal_data_exposure_percentage: 0.0,
            estimated_downtime_hours: 0.0,
            affected_users_percentage: 0.0,
            known_exploited: cveIntel.kev,
            patch_available: true,
            mission_critical: assetCriticality >= 8,
            asset_contains_federal_data: false
          }),
        });
        
        if (!response.ok) {
          setError('VDR API error: ' + response.status);
          return;
        }
        
        const vdrData = await response.json();
        setVdrResult(vdrData);
        return;
      }
      
      // Handle other frameworks
      const response = await fetch(API_ENDPOINTS.score(), {
        method: 'POST',
        headers,
        body: JSON.stringify({
          cve_id: cveId,
          asset_criticality: assetCriticality,
          is_internet_facing: isInternetFacing,
          framework: selectedFramework
        })
      });
      
      if (!response.ok) {
        setError('API error: ' + response.status);
        return;
      }
      
      const result = await response.json();
      setRiskScore(result);
    } catch (err) {
      setError('Network or parsing error.');
    }
  };

  const getPriorityVariant = (priority: string) => {
    switch (priority) {
      case 'CRITICAL': return 'destructive';
      case 'HIGH': return 'destructive';
      case 'MEDIUM': return 'secondary';
      case 'LOW': return 'outline';
      case 'INFORMATIONAL': return 'outline';
      default: return 'secondary';
    }
  };

  

  return (
    <Card className="w-full max-w-4xl mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Transparent Risk Assessment
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {!isAuthenticated && (
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-4">
            <div className="flex items-center gap-2 text-blue-800 dark:text-blue-200">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm font-medium">Try Before You Sign Up</span>
            </div>
            <p className="text-blue-700 dark:text-blue-300 text-sm mt-1">
              You can calculate risk scores without creating an account. 
              <button 
                onClick={() => loginWithRedirect()} 
                className="text-blue-600 dark:text-blue-400 underline hover:text-blue-800 dark:hover:text-blue-200 ml-1"
              >
                Sign in
              </button> 
              to unlock:
            </p>
            <ul className="text-blue-700 dark:text-blue-300 text-xs mt-2 ml-4 list-disc">
              <li>Save assessment history</li>
              <li>Batch processing with CSV uploads</li>
              <li>Advanced AI insights and analytics</li>
              <li>API key management</li>
              <li>Compliance reporting</li>
            </ul>
          </div>
        )}
        
        <FrameworkSelector 
          selectedFramework={selectedFramework}
          onFrameworkChange={setSelectedFramework}
        />
        
        <div>
          <label className="block text-sm font-medium mb-2">CVE ID</label>
          <Input
            value={cveId}
            onChange={(e) => setCveId(e.target.value)}
            placeholder="CVE-2025-1234"
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">
            Asset Criticality: {assetCriticality}
          </label>
          <Slider
            value={[assetCriticality]}
            onValueChange={(value) => setAssetCriticality(value[0])}
            max={10}
            min={1}
            step={1}
          />
        </div>
        
        <div className="flex items-center space-x-2">
          <input
            type="checkbox"
            checked={isInternetFacing}
            onChange={(e) => setIsInternetFacing(e.target.checked)}
            title="Internet Facing"
            placeholder="Internet Facing"
          />
          <label>Internet Facing</label>
        </div>
        
        <Button onClick={calculateRisk} className="w-full">
          Calculate Risk Score
        </Button>
        
        {error && (
          <div className="mt-4 p-2 bg-red-100 text-red-700 rounded">{error}</div>
        )}
        
        {vdrResult && (
          <div className="mt-6 space-y-6">
            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-blue-900 mb-4">FedRAMP VDR Assessment</h3>
              
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="text-center p-4 bg-white rounded-lg border">
                  <div className="text-2xl font-bold text-blue-900">{vdrResult.impact_rating}</div>
                  <div className="text-sm text-blue-600">Impact Rating</div>
                </div>
                <div className="text-center p-4 bg-white rounded-lg border">
                  <div className={`text-2xl font-bold ${vdrResult.lev.status ? 'text-red-600' : 'text-green-600'}`}>
                    {vdrResult.lev.status ? 'LEV' : 'NLEV'}
                  </div>
                  <div className="text-sm text-blue-600">Likely Exploitable</div>
                </div>
                <div className="text-center p-4 bg-white rounded-lg border">
                  <div className={`text-2xl font-bold ${vdrResult.irv.status ? 'text-red-600' : 'text-green-600'}`}>
                    {vdrResult.irv.status ? 'IRV' : 'NIRV'}
                  </div>
                  <div className="text-sm text-blue-600">Internet Reachable</div>
                </div>
                <div className="text-center p-4 bg-white rounded-lg border">
                  <div className="text-2xl font-bold text-blue-900">{vdrResult.timeline.category}</div>
                  <div className="text-sm text-blue-600">Timeline Category</div>
                </div>
              </div>
              
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-blue-900 mb-2">LEV Assessment</h4>
                  <div className="bg-white p-3 rounded border">
                    <p className="text-sm text-gray-700 mb-2">
                      Status: <span className={`font-medium ${vdrResult.lev.status ? 'text-red-600' : 'text-green-600'}`}>
                        {vdrResult.lev.status ? 'Likely Exploitable' : 'Not Likely Exploitable'}
                      </span>
                    </p>
                    <ul className="text-sm text-gray-600 space-y-1">
                      {Array.isArray(vdrResult.lev.reasons) && vdrResult.lev.reasons.map((reason, idx) => (
                        <li key={idx}>• {reason}</li>
                      ))}
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="font-medium text-blue-900 mb-2">IRV Assessment</h4>
                  <div className="bg-white p-3 rounded border">
                    <p className="text-sm text-gray-700 mb-2">
                      Status: <span className={`font-medium ${vdrResult.irv.status ? 'text-red-600' : 'text-green-600'}`}>
                        {vdrResult.irv.status ? 'Internet Reachable' : 'Not Internet Reachable'}
                      </span>
                    </p>
                    <ul className="text-sm text-gray-600 space-y-1">
                      {Array.isArray(vdrResult.irv.reasons) && vdrResult.irv.reasons.map((reason, idx) => (
                        <li key={idx}>• {reason}</li>
                      ))}
                    </ul>
                  </div>
                </div>
                
                <div>
                  <h4 className="font-medium text-blue-900 mb-2">Timeline Requirements</h4>
                  <div className="bg-white p-3 rounded border">
                    <p className="text-sm text-gray-700 mb-2">
                      Category: <span className="font-medium">{vdrResult.timeline.category}</span>
                    </p>
                    <p className="text-sm text-gray-600">
                      Remediation Timeline: {vdrResult.timeline.days} days
                    </p>
                  </div>
                </div>
                
                <div>
                  <h4 className="font-medium text-blue-900 mb-2">Compliance Status</h4>
                  <div className="bg-white p-3 rounded border">
                    <p className="text-sm text-gray-700 mb-2">
                      Status: <span className={`font-medium ${vdrResult.incident_response_required ? 'text-red-600' : 'text-green-600'}`}>
                        {vdrResult.incident_response_required ? 'Incident Response Required' : 'Standard Process'}
                      </span>
                    </p>
                    <p className="text-sm text-gray-600">
                      Framework: {vdrResult.framework_version}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
        
        {riskScore && (
          <div className="mt-6 space-y-6">
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="calculation">Calculation</TabsTrigger>
                <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                <TabsTrigger value="audit">Audit Trail</TabsTrigger>
              </TabsList>
              
              <TabsContent value="overview" className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center p-4 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-gray-900">{riskScore.risk_score.toFixed(1)}</div>
                    <div className="text-sm text-gray-600">Risk Score</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 rounded-lg">
                    <Badge variant={getPriorityVariant(riskScore.priority)}>
                      {riskScore.priority}
                    </Badge>
                    <div className="text-sm text-gray-600 mt-1">Priority</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-gray-900">{riskScore.timeline_days}</div>
                    <div className="text-sm text-gray-600">Timeline (days)</div>
                  </div>
                
                </div>
                
                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700 rounded-lg p-4">
                  <h3 className="font-medium text-blue-900 dark:text-blue-100 mb-2">Quick Summary</h3>
                  <p className="text-sm text-blue-700 dark:text-blue-300">{riskScore.explanation}</p>
                </div>
              </TabsContent>
              
              <TabsContent value="calculation" className="space-y-4">
                <div className="space-y-4">
                  <div className="bg-gray-50 p-4 rounded-lg">
                    <h3 className="font-medium mb-2">Base Risk Components</h3>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span>Technical Severity (CVSS):</span>
                        <span className="font-mono">{riskScore.calculation_breakdown.base_risk.components.technical_severity.value} × {riskScore.calculation_breakdown.base_risk.components.technical_severity.weight} = {riskScore.calculation_breakdown.base_risk.components.technical_severity.contribution.toFixed(2)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Business Impact:</span>
                        <span className="font-mono">{riskScore.calculation_breakdown.base_risk.components.business_impact.value} × {riskScore.calculation_breakdown.base_risk.components.business_impact.weight} = {riskScore.calculation_breakdown.base_risk.components.business_impact.contribution.toFixed(2)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Exploit Likelihood:</span>
                        <span className="font-mono">{riskScore.calculation_breakdown.base_risk.components.exploit_likelihood.value} × {riskScore.calculation_breakdown.base_risk.components.exploit_likelihood.weight} = {riskScore.calculation_breakdown.base_risk.components.exploit_likelihood.contribution.toFixed(2)}</span>
                      </div>
                      <div className="border-t pt-2 font-medium">
                        <div className="flex justify-between">
                          <span>Base Risk:</span>
                          <span className="font-mono">{riskScore.calculation_breakdown.base_risk.value.toFixed(2)}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="bg-yellow-50 p-4 rounded-lg">
                    <h3 className="font-medium mb-2">Context Multipliers</h3>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span>Reachability:</span>
                        <span className="font-mono">{riskScore.calculation_breakdown.context_multipliers.reachability.value.toFixed(1)}x</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Threat Intelligence:</span>
                        <span className="font-mono">{riskScore.calculation_breakdown.context_multipliers.threat_intelligence.value.toFixed(1)}x</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="bg-green-50 p-4 rounded-lg">
                    <h3 className="font-medium mb-2">Mitigation Factors</h3>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span>Total Risk Reduction:</span>
                        <span className="font-mono">{(riskScore.calculation_breakdown.mitigation_factors.total_reduction * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="recommendations" className="space-y-4">
                <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-700 rounded-lg p-4">
                  <h3 className="font-medium text-orange-900 dark:text-orange-100 mb-3 flex items-center gap-2">
                    <Lightbulb className="h-4 w-4" />
                    Actionable Recommendations
                  </h3>
                  <div className="space-y-2">
                    {riskScore.recommendations.map((rec, index) => (
                      <div key={index} className="flex items-start gap-2">
                        <div className="w-2 h-2 bg-orange-500 rounded-full mt-2 flex-shrink-0"></div>
                        <span className="text-sm text-orange-800 dark:text-orange-200">{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700 rounded-lg p-4">
                  <h3 className="font-medium text-blue-900 dark:text-blue-100 mb-2">Data Freshness</h3>
                  <div className="space-y-1 text-sm text-blue-700 dark:text-blue-300">
                    {Object.entries(riskScore.data_freshness).map(([key, value]) => (
                      <div key={key} className="flex justify-between">
                        <span className="capitalize">{key.replace('_', ' ')}:</span>
                        <span>{value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="audit" className="space-y-4">
                <div className="bg-gray-50 p-4 rounded-lg">
                  <h3 className="font-medium mb-3 flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    Calculation Audit Trail
                  </h3>
                  <div className="space-y-2 text-sm">
                    <div><strong>Calculation Timestamp:</strong> {new Date(riskScore.audit_trail.calculation_timestamp).toLocaleString()}</div>
                    <div><strong>Framework Version:</strong> {riskScore.audit_trail.framework_version}</div>
                    <div><strong>CVE ID:</strong> {riskScore.audit_trail.input_parameters.cve_id}</div>
                  </div>
                  
                  <h4 className="font-medium mt-4 mb-2">Calculation Steps:</h4>
                  <div className="space-y-1 text-sm">
                    {riskScore.audit_trail.calculation_steps.map((step: string, index: number) => (
                      <div key={index} className="flex items-center gap-2">
                        <div className="w-1 h-1 bg-gray-500 rounded-full"></div>
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </div>
        )}
      </CardContent>
    </Card>
  );
}; 