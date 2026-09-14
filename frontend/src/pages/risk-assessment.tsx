import { API_ENDPOINTS } from "../config/api";
import React, { useState, useEffect } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { Alert, AlertDescription } from '../components/ui/alert';
import { FrameworkGuide } from '../components/ui/framework-guide';
import { AssetCriticalityGuide } from '../components/ui/asset-criticality-guide';
import { FileUpload } from '../components/FileUpload';
import { RiskStepper } from '../components/ui/risk-stepper';
import { DataChip } from '../components/ui/data-chip';
import { SummaryRail } from '../components/ui/summary-rail';
import { apiCall } from '../lib/utils';
import {
  Target,
  Upload,
  Calculator,
  FileText,
  Download,
  AlertTriangle,
  CheckCircle,
  Clock,
  XCircle,
  Lightbulb,
  BarChart3,
  ChevronLeft,
  ChevronRight,
  Settings,
  Network,
  RefreshCw,
  Save,
  Share
} from 'lucide-react';

// Human-readable names for the CVE data sources the backend can fall back to.
const SOURCE_LABELS: Record<string, string> = {
  nvd: 'NVD',
  cvedb: 'Shodan CVEDB',
};

interface RiskResult {
  cve_id: string;
  risk_score: number;
  priority: string;
  timeline_days: number;
  explanation: string;
  components: Record<string, number>;
  calculation_breakdown?: Record<string, number>;
  confidence_score?: number;
  recommendations?: string[];
  data_freshness?: Record<string, string>;
  audit_trail?: Record<string, any>;
  cve_intelligence?: Record<string, any>;
  status: 'success' | 'error';
  error?: string;
}

interface VDRResult {
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
    service_degradation_hours: number;
    federal_data_exposure_percentage: number;
    estimated_downtime_hours: number;
    affected_users_percentage: number;
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

const steps = [
  { id: 1, title: "Select", description: "Framework & CVE" },
  { id: 2, title: "Impact", description: "& Mitigation" },
  { id: 3, title: "Environment", description: "& Reachability" },
  { id: 4, title: "Review", description: "& Calculate" },
];

// Framework-specific step limits and derived steps list
const maxStepForFramework = (fw: string): number => {
  switch (fw) {
    case 'enhanced':
      return 4;
    case 'mitigation-contextual':
      return 4;
    case 'risk-based':
      return 4;
    case 'fedramp-vdr':
      return 4;
    default:
      return 3;
  }
};

// Whether the given step is actually shown for a framework
const isStepVisibleForFramework = (fw: string, stepId: number): boolean => {
  if (stepId === 1) return true;
  if (stepId === 2) return fw === 'mitigation-contextual' || fw === 'fedramp-vdr' || fw === 'risk-based';
  if (stepId === 3) return fw === 'risk-based' || fw === 'fedramp-vdr';
  if (stepId === 4) return fw === 'fedramp-vdr' || fw === 'risk-based' || fw === 'mitigation-contextual' || fw === 'enhanced';
  return false;
};

const getVisibleStepsForFramework = (fw: string) => {
  const max = maxStepForFramework(fw);
  return steps.filter(s => s.id <= max && isStepVisibleForFramework(fw, s.id));
};

const getNextVisibleStepId = (fw: string, current: number): number | null => {
  const max = maxStepForFramework(fw);
  for (let s = current + 1; s <= max; s++) {
    if (isStepVisibleForFramework(fw, s)) return s;
  }
  return null;
};

const getPrevVisibleStepId = (fw: string, current: number): number | null => {
  for (let s = current - 1; s >= 1; s--) {
    if (isStepVisibleForFramework(fw, s)) return s;
  }
  return null;
};

// Normalize stepper display to show sequential numbers (1..N) regardless of hidden steps
const getNormalizedStepper = (fw: string, cs: number) => {
  const visible = getVisibleStepsForFramework(fw);
  const stepsForStepper = visible.map((s, idx) => ({
    id: idx + 1,
    title: s.title,
    description: s.description
  }));
  const index = visible.findIndex(s => s.id === cs);
  const current = index >= 0 ? index + 1 : 1;
  return { stepsForStepper, current };
};

const RiskAssessment: React.FC = () => {
  const { isAuthenticated, loginWithRedirect, getAccessTokenSilently } = useAuth0();

  // Helper functions for VDR display
  const getImpactColor = (level: string) => {
    const colors = {
      'N5': 'bg-red-900 text-white',
      'N4': 'bg-red-600 text-white', 
      'N3': 'bg-orange-500 text-white',
      'N2': 'bg-yellow-500 text-black',
      'N1': 'bg-green-500 text-white'
    };
    return colors[level as keyof typeof colors] || 'bg-gray-500';
  };

  const formatTimeline = (days: number) => {
    if (days < 1) return `${Math.round(days * 24)} hours`;
    if (days < 7) return `${Math.round(days)} days`;
    return `${Math.round(days)} days`;
  };

  // Step navigation functions
  const nextStep = () => {
    const max = maxStepForFramework(selectedFramework);
    if (currentStep >= max) return;
    const next = getNextVisibleStepId(selectedFramework, currentStep);
    if (next) setCurrentStep(next);
  };

  const prevStep = () => {
    if (currentStep <= 1) return;
    const prev = getPrevVisibleStepId(selectedFramework, currentStep);
    if (prev) setCurrentStep(prev);
  };

  // Validation functions
  const canProceedToStep2 = () => {
    return cveId.trim() !== '';
  };

  const canProceedToStep3 = () => {
    return true; // For now, allow proceeding to step 3
  };

  const canProceedToStep4 = () => {
    return true; // For now, allow proceeding to step 4
  };

  // CVE ID validation function
  const isValidCveId = (cveId: string) => {
    const cvePattern = /^CVE-\d{4}-\d{4,7}$/i;
    return cvePattern.test(cveId.trim());
  };

  const canCalculate = () => {
    return isValidCveId(cveId) && !isCalculating && currentStep === maxStepForFramework(selectedFramework);
  };

  const [activeTab, setActiveTab] = useState('individual');
  
  // Individual calculation state
  const [cveId, setCveId] = useState('');
  const [cveIdError, setCveIdError] = useState<string>('');
  const [assetCriticality, setAssetCriticality] = useState(5);
  const [isInternetFacing, setIsInternetFacing] = useState(false);
  const [selectedFramework, setSelectedFramework] = useState('enhanced');
  const [individualResult, setIndividualResult] = useState<RiskResult | null>(null);
  const [vdrResult, setVdrResult] = useState<VDRResult | null>(null);
  const [individualError, setIndividualError] = useState<string | null>(null);
  const [isCalculating, setIsCalculating] = useState(false);
  const [showGuidance, setShowGuidance] = useState(false);
  const [showScoringGuide, setShowScoringGuide] = useState(false);

  // CVE intelligence auto-fetch state
  const [cveIntel, setCveIntel] = useState<{
    loading: boolean;
    epss: number | null;
    cvss: number | null;
    kev: boolean | null;
    patchAvailable: boolean | null;
    error: string | null;
  }>({ loading: false, epss: null, cvss: null, kev: null, patchAvailable: null, error: null });

  // Compute lightweight validation warnings for the Summary rail
  const computeWarnings = (): string[] => {
    const warnings: string[] = [];
    if (selectedFramework === 'fedramp-vdr') {
      if (vdrInputs.federal_data_exposure_percentage > 0 && !vdrInputs.asset_contains_federal_data) {
        warnings.push('Federal Data Exposure > 0% but "Contains Federal Data" is off.');
      }
      if (vdrInputs.internet_reachable && cveIntel.kev === true) {
        warnings.push('Known exploited vulnerability is internet-reachable. Prioritize mitigation.');
      }
    } else {
      if (assetCriticality >= 9 && isInternetFacing) {
        warnings.push('High criticality asset is internet facing.');
      }
    }
    return warnings;
  };

  // Compact FedRAMP VDR matrix toggle in scoring guide
  const [showVdrMatrix, setShowVdrMatrix] = useState(false);
  const [vdrAuthLevel, setVdrAuthLevel] = useState<'low' | 'moderate' | 'high'>('moderate');

  // Auto-fetch CVE metadata on blur using the existing score endpoint
  const fetchCveIntel = async (id: string) => {
    const cve = id.trim();
    if (!cve) return;
    setCveIntel(prev => ({ ...prev, loading: true, error: null }));
    try {
      // Use the existing score endpoint which fetches all CVE data internally
      const scoreRequest = {
        cve_id: cve,
        asset_criticality: 5, // Default value for fetching data
        is_internet_facing: false, // Default value for fetching data
        framework: 'enhanced', // Use enhanced framework to get comprehensive data
        preventive_controls: [],
        detective_controls: [],
        response_controls: []
      };

      // Call the score endpoint which fetches all CVE data internally
      const result = await apiCall(API_ENDPOINTS.score(), {
        method: 'POST',
        body: JSON.stringify(scoreRequest)
      }, isAuthenticated ? getAccessTokenSilently : undefined);

      // Extract CVE intelligence data from the score response
      // The backend fetches EPSS, CVSS, and KEV data internally and returns it in cve_intelligence
      const cveIntel = result.cve_intelligence || {};

      const epss = cveIntel.epss_score || 0;
      const cvss = cveIntel.cvss_score || 0;
      const kev = cveIntel.cisa_kev || false;

      setCveIntel({
        loading: false,
        epss,
        cvss,
        kev,
        patchAvailable: null, // Backend would need to add this
        error: null,
      });

      // Also reflect EPSS/KEV into VDR inputs for display coherence
      setVdrInputs(prev => ({ 
        ...prev, 
        epss, 
        known_exploited: kev,
        threat_intel_tags: kev ? ["cisa_kev"] : []
      }));
    } catch (err) {
      setCveIntel(prev => ({ ...prev, loading: false, error: 'Auto-fetch failed. Try again.' }));
    }
  };

  // Mitigation controls state
  const [mitigationControls, setMitigationControls] = useState({
    preventive_controls: [] as string[],
    detective_controls: [] as string[],
    response_controls: [] as string[]
  });

  // VDR-specific state
  const [showInfoBoxes, setShowInfoBoxes] = useState({
    fedrampDefinition: true,
    payloadCapabilities: true,
    autoPopulatedData: true,
    irvDefinition: true
  });
  
  const [vdrInputs, setVdrInputs] = useState({
    // Authorization level for timeline calculation
    authorization_level: 'moderate',
    
    // Asset context
    asset_criticality_rating: 'medium', // Low, Medium, High, Mission Critical
    
    // Federal impact fields (required for N1-N5 classification)
    service_degradation_hours: 0,
    federal_data_exposure_percentage: 0,
    estimated_downtime_hours: 0,
    affected_users_percentage: 0,
    
    // System architecture
    internet_reachable: false,
    payload_processing_capabilities: [] as string[], // For FRD-ALL-24 compliance
    
    // Mitigation status
    current_mitigation_level: 'none', // None, Partial, Full
    mitigation_effectiveness: 0,
    compensating_controls: [] as string[],
    
    // Auto-populated fields
    epss: 0, // Auto-populated
    known_exploited: false, // Auto-populated
    patch_available: false, // Auto-populated
    mission_critical: false,
    asset_contains_federal_data: false,
    
    // Context factors (FRR-VDR-10)
    mission_criticality: 5,
    reachability_paths: [] as string[],
    // exploitation_likelihood: Auto-populated from EPSS
    vulnerability_discovery_ease: 0,
    inventory_impact_pct: 0,
    granted_privilege_level: 'none',
    vulnerability_chaining_indicators: [] as string[],
    threat_intel_tags: [] as string[]
  });

  // Batch processing state
  const [batchResults, setBatchResults] = useState<RiskResult[]>([]);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [isProcessingBatch, setIsProcessingBatch] = useState(false);

  // Step navigation state
  const [currentStep, setCurrentStep] = useState(1);

  // Clamp current step whenever framework changes
  useEffect(() => {
    const max = maxStepForFramework(selectedFramework);
    setCurrentStep(prev => (prev > max ? max : prev < 1 ? 1 : prev));
  }, [selectedFramework]);

  // Restore state after authentication
  useEffect(() => {
    if (isAuthenticated) {
      const savedState = localStorage.getItem('vulnrisk_return_state');
      if (savedState) {
        try {
          const state = JSON.parse(savedState);
          setCveId(state.cveId || '');
          setAssetCriticality(state.assetCriticality || 5);
          setIsInternetFacing(state.isInternetFacing || false);
          setSelectedFramework(state.selectedFramework || 'enhanced');
          setActiveTab(state.activeTab || 'individual');
          if (state.mitigationControls) {
            setMitigationControls(state.mitigationControls);
          }
          localStorage.removeItem('vulnrisk_return_state');
        } catch (error) {
          console.error('Error restoring state:', error);
          localStorage.removeItem('vulnrisk_return_state');
        }
      }
    }
  }, [isAuthenticated]);

  const calculateIndividualRisk = async () => {

    if (!cveId.trim()) {
      setIndividualError('Please enter a CVE ID');
      return;
    }

    setIsCalculating(true);
    setIndividualError(null);
    setIndividualResult(null);
    setVdrResult(null);

    try {
      // Handle VDR framework separately
      if (selectedFramework === 'fedramp-vdr') {
        const requestBody = {
          cve_id: cveId.trim(),
          // Authorization level for timeline calculation
          authorization_level: vdrInputs.authorization_level,
          
          // Asset context
          asset_criticality_rating: vdrInputs.asset_criticality_rating,
          
          // Federal impact assessment fields
          service_degradation_hours: vdrInputs.service_degradation_hours,
          federal_data_exposure_percentage: vdrInputs.federal_data_exposure_percentage,
          estimated_downtime_hours: vdrInputs.estimated_downtime_hours,
          affected_users_percentage: vdrInputs.affected_users_percentage,
          
          // System architecture
          internet_reachable: vdrInputs.internet_reachable,
          payload_processing_capabilities: vdrInputs.payload_processing_capabilities,
          
          // Mitigation status
          current_mitigation_level: vdrInputs.current_mitigation_level,
          mitigation_effectiveness: vdrInputs.mitigation_effectiveness,
          compensating_controls: vdrInputs.compensating_controls,
          
          // Auto-populated fields - use auto-fetched data when available
          epss: cveIntel.epss || vdrInputs.epss,
          known_exploited: cveIntel.kev || vdrInputs.known_exploited,
          patch_available: vdrInputs.patch_available,
          mission_critical: vdrInputs.mission_critical,
          asset_contains_federal_data: vdrInputs.asset_contains_federal_data,
          
          // Context factors (FRR-VDR-10)
          mission_criticality: vdrInputs.mission_criticality,
          reachability_paths: vdrInputs.reachability_paths,
          // exploitation_likelihood: Auto-populated from EPSS
          vulnerability_discovery_ease: vdrInputs.vulnerability_discovery_ease,
          inventory_impact_pct: vdrInputs.inventory_impact_pct,
          granted_privilege_level: vdrInputs.granted_privilege_level,
          vulnerability_chaining_indicators: vdrInputs.vulnerability_chaining_indicators,
          // Use auto-fetched KEV status for threat intelligence tags
          threat_intel_tags: cveIntel.kev ? ["cisa_kev"] : vdrInputs.threat_intel_tags
        };

        const result = await apiCall(API_ENDPOINTS.fedrampVDRAssess(), {
          method: 'POST',
          body: JSON.stringify(requestBody)
        });

        console.log('VDR Result received:', result);
        setVdrResult(result);
        // Results are now displayed immediately in the main content area
        // No need to navigate to step 4
        return;
      }

      // Handle other frameworks (non-VDR): send only explicit control arrays
      const requestBody = {
        cve_id: cveId.trim(),
        asset_criticality: assetCriticality,
        is_internet_facing: isInternetFacing,
        framework: selectedFramework,
        // Include mitigation controls (explicit only)
        preventive_controls: mitigationControls.preventive_controls,
        detective_controls: mitigationControls.detective_controls,
        response_controls: mitigationControls.response_controls
      };

      const result = await apiCall(API_ENDPOINTS.score(), {
        method: 'POST',
        body: JSON.stringify(requestBody)
      }, isAuthenticated ? getAccessTokenSilently : undefined);

      console.log('Individual Result received:', result);
      setIndividualResult({
        ...result,
        cve_intelligence: result.cve_intelligence,
        status: 'success'
      });

      // Results are now displayed immediately in the main content area
      // No need to navigate to step 4
    } catch (err) {
      setIndividualError(err instanceof Error ? err.message : 'Network error');
    } finally {
      setIsCalculating(false);
    }
  };

  const processBatchFile = async (file: File) => {
    if (!isAuthenticated) {
      // Store the current state so we can return to it after authentication
      const currentState = {
        selectedFramework,
        mitigationControls,
        activeTab: 'batch'
      };
      localStorage.setItem('vulnrisk_return_state', JSON.stringify(currentState));
      
      // Note: We can't store the file, so we'll need to ask user to re-upload
      await loginWithRedirect({
        appState: { returnTo: '/risk-assessment' }
      });
      return;
    }

    setIsProcessingBatch(true);
    setBatchError(null);
    setBatchResults([]);

    try {
      const text = await file.text();
      const lines = text.split('\n').filter(line => line.trim());
      
      // Parse CSV format: CVE_ID,Asset_Criticality,Internet_Facing
      const vulnerabilities = lines.slice(1).map(line => {
        const [cve, criticality, internetFacing] = line.split(',').map(field => field.trim());
        return {
          cve_id: cve,
          asset_criticality: parseInt(criticality) || 5,
          is_internet_facing: internetFacing?.toLowerCase() === 'true'
        };
      });

      const results: RiskResult[] = [];

      for (const vuln of vulnerabilities) {
        try {
          const result = await apiCall(API_ENDPOINTS.score(), {
            method: 'POST',
            body: JSON.stringify({
              ...vuln,
              framework: selectedFramework,
              // Include mitigation controls for batch processing
              preventive_controls: mitigationControls.preventive_controls,
              detective_controls: mitigationControls.detective_controls,
              response_controls: mitigationControls.response_controls
            })
          }, isAuthenticated ? getAccessTokenSilently : undefined);
          
          results.push({
            ...result,
            status: 'success'
          });
        } catch (err) {
          results.push({
            cve_id: vuln.cve_id,
            risk_score: 0,
            priority: 'ERROR',
            timeline_days: 0,
            explanation: '',
            components: {},
            status: 'error',
            error: 'Network error'
          });
        }
      }

      setBatchResults(results);
    } catch (err) {
      setBatchError('Error processing file. Please ensure it\'s a valid CSV file.');
    } finally {
      setIsProcessingBatch(false);
    }
  };

  const exportResults = () => {
    if (batchResults.length === 0) return;

    const csvContent = [
      'CVE_ID,Risk_Score,Priority,Timeline_Days,Status,Error',
      ...batchResults.map(result => 
        `${result.cve_id},${result.risk_score},${result.priority},${result.timeline_days},${result.status},${result.error || ''}`
      )
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'risk_assessment_results.csv';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const getPriorityIcon = (priority: string) => {
    switch (priority.toUpperCase()) {
      case 'CRITICAL':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'HIGH':
        return <AlertTriangle className="w-4 h-4 text-orange-500" />;
      case 'MEDIUM':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'LOW':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      default:
        return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 border-red-200 dark:border-red-700';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200 border-orange-200 dark:border-orange-700';
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 border-yellow-200 dark:border-yellow-700';
      case 'LOW':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 border-blue-200 dark:border-blue-700';
      case 'INFORMATIONAL':
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200 border-gray-200 dark:border-gray-600';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200 border-gray-200 dark:border-gray-600';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      <div className="container mx-auto pt-0 sm:pt-0 lg:pt-0 pb-2 sm:pb-3 lg:pb-4 pl-2 sm:pl-3 lg:pl-4 pr-2 sm:pr-2 lg:pr-72 xl:pr-72 2xl:pr-72 space-y-2 sm:space-y-3 lg:space-y-4 max-w-full dark:[&_.text-gray-900]:text-gray-100 dark:[&_.text-gray-800]:text-gray-200 dark:[&_.text-gray-700]:text-gray-300 dark:[&_.text-gray-600]:text-gray-400 dark:[&_.bg-white]:bg-dark-500 dark:[&_.bg-white\/95]:bg-dark-600\/95 dark:[&_.border-gray-200]:border-gray-700 dark:[&_.border-gray-300]:border-gray-600 dark:[&_.text-gray-900]:text-gray-100">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 sm:gap-3 lg:gap-4">
          <div className="flex-1">
            <h1 className="text-xl sm:text-2xl lg:text-3xl font-bold flex items-center text-gray-900 dark:text-white">
              <Target className="w-5 h-5 sm:w-6 sm:h-6 lg:w-8 lg:h-8 mr-2 text-primary-500" />
              Risk Assessment
            </h1>
            <p className="text-xs sm:text-sm lg:text-base text-gray-600 dark:text-gray-300">
              Fast, accurate, and consistent vulnerability risk scoring across all frameworks
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="w-full sm:w-auto px-3 py-2 text-sm"
            onClick={() => {
              setCurrentStep(1);
              setCveId('');
              setAssetCriticality(5);
              setIsInternetFacing(false);
              setSelectedFramework('enhanced');
              setIndividualResult(null);
              setVdrResult(null);
              setIndividualError(null);
              setCveIntel({ loading: false, epss: null, cvss: null, kev: null, patchAvailable: null, error: null });
            }}
          >
            <RefreshCw className="h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2" />
            <span className="hidden sm:inline">New Assessment</span>
            <span className="sm:hidden">New</span>
          </Button>
        </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-1 sm:space-y-2">
        <TabsList className="grid w-full grid-cols-3 h-auto p-0.5 gap-0.5">
          <TabsTrigger value="individual" className="flex items-center text-xs sm:text-sm px-1 sm:px-2 lg:px-4 py-2 sm:py-3">
            <Calculator className="w-3 h-3 sm:w-4 sm:h-4 mr-1 sm:mr-2" />
            <span className="hidden sm:inline">Risk Assessment</span>
            <span className="sm:hidden">Risk</span>
          </TabsTrigger>
          <TabsTrigger value="batch" className="flex items-center text-xs sm:text-sm px-1 sm:px-2 lg:px-4 py-2 sm:py-3">
            <Upload className="w-3 h-3 sm:w-4 sm:h-4 mr-1 sm:mr-2" />
            <span className="hidden sm:inline">Batch Processing</span>
            <span className="sm:hidden">Batch</span>
          </TabsTrigger>
          <TabsTrigger value="results" className="flex items-center text-xs sm:text-sm px-1 sm:px-2 lg:px-4 py-2 sm:py-3">
            <FileText className="w-3 h-3 sm:w-4 sm:h-4 mr-1 sm:mr-2" />
            <span className="hidden sm:inline">Results History</span>
            <span className="sm:hidden">History</span>
          </TabsTrigger>
        </TabsList>

        {/* Individual Assessment Tab */}
        <TabsContent value="individual" className="space-y-2 sm:space-y-3 lg:space-y-4">
          <div className="relative">
            {/* Main content area */}
            <div className="flex-1 max-w-6xl xl:max-w-7xl space-y-2 sm:space-y-3 lg:space-y-4 min-w-0 pr-0 lg:pr-72 xl:pr-72 2xl:pr-72">
              {/* Stepper */}
              {(() => {
                const norm = getNormalizedStepper(selectedFramework, currentStep);
                return <RiskStepper currentStep={norm.current} steps={norm.stepsForStepper} />;
              })()}

              {/* Results Display - Show immediately after calculation */}
              {individualResult && (
                <Card className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border-blue-200 dark:border-blue-700 shadow-lg">
                  <CardHeader className="pb-3 sm:pb-4">
                    <CardTitle className="flex items-center gap-2 text-blue-900 dark:text-blue-100 text-base sm:text-lg lg:text-xl">
                      <CheckCircle className="h-4 w-4 sm:h-5 sm:w-5 lg:h-6 lg:w-6 text-green-600" />
                      Risk Assessment Complete
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 lg:gap-6">
                      <div className="text-center">
                        <div className="text-3xl font-bold text-blue-900 dark:text-blue-100 mb-2">
                          {individualResult.risk_score.toFixed(1)}
                        </div>
                        <Badge
                          variant="secondary"
                          className={`${getPriorityColor(individualResult.priority)} text-base px-4 py-2`}
                        >
                          {individualResult.priority} Priority
                        </Badge>
                      </div>
                      <div className="text-center">
                        <div className="text-sm text-gray-600 dark:text-gray-300 mb-1">Timeline</div>
                        <div className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                          {individualResult.timeline_days} days
                        </div>
                      </div>
                      <div className="text-center">
                        <div className="text-sm text-gray-600 dark:text-gray-300 mb-1">CVE ID</div>
                        <div className="text-sm font-mono text-gray-900 dark:text-gray-100">
                          {individualResult.cve_id}
                        </div>
                      </div>
                    </div>
                    {(individualResult.recommendations?.length || individualResult.audit_trail?.timestamp) && (
                      <div className="mt-3 sm:mt-4 p-2 sm:p-3 bg-white dark:bg-gray-800 rounded-lg border border-blue-200 dark:border-blue-700">
                        <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Assessment Details</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 sm:gap-2 text-xs">
                          {individualResult.recommendations && individualResult.recommendations.length > 0 && (
                            <div className="col-span-1 sm:col-span-2 py-1">
                              <span className="font-medium text-gray-600 dark:text-gray-300">Recommendations:</span>
                              <ul className="list-disc list-inside mt-1">
                                {individualResult.recommendations.map((rec, idx) => (
                                  <li key={idx} className="text-xs text-gray-600 dark:text-gray-300">{rec}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                          {individualResult.audit_trail && individualResult.audit_trail.timestamp && (
                            <div className="col-span-1 sm:col-span-2 py-1">
                              <span className="font-medium text-gray-600 dark:text-gray-300">Assessment Time:</span>
                              <div className="text-xs mt-1 text-gray-600 dark:text-gray-300">
                                {new Date(individualResult.audit_trail.timestamp).toLocaleString()}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {individualResult.components && (
                      <div className="mt-3 sm:mt-4 p-2 sm:p-3 bg-white dark:bg-gray-800 rounded-lg border border-blue-200 dark:border-blue-700">
                        <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Risk Components</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 sm:gap-2 text-xs">
                          {Object.entries(individualResult.components).map(([key, value]) => (
                            <div key={key} className="flex justify-between py-1">
                              <span className="capitalize text-gray-600 dark:text-gray-300">{key.replace('_', ' ')}:</span>
                              <span className="font-medium text-gray-900 dark:text-gray-100">{typeof value === 'number' ? value.toFixed(2) : typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {individualResult.explanation && (
                      <div className="mt-3 sm:mt-4 p-2 sm:p-3 bg-white dark:bg-gray-800 rounded-lg border border-blue-200 dark:border-blue-700">
                        <p className="text-sm text-gray-700 dark:text-gray-300">
                          <strong>Explanation:</strong> {individualResult.explanation}
                        </p>
                      </div>
                    )}

                    {individualResult.cve_intelligence && (
                      <div className="mt-3 sm:mt-4 p-2 sm:p-3 bg-white dark:bg-gray-800 rounded-lg border border-blue-200 dark:border-blue-700">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300">CVE Intelligence</h4>
                          {individualResult.cve_intelligence.data_source && (
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                                individualResult.cve_intelligence.provenance?.used_fallback
                                  ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200'
                                  : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200'
                              }`}
                              title={
                                individualResult.cve_intelligence.provenance?.used_fallback
                                  ? `Primary source returned no data. Served by the backup source; ${individualResult.cve_intelligence.provenance?.degraded_fields?.length || 0} CVSS vector field(s) unavailable.`
                                  : 'Served by the primary data source'
                              }
                            >
                              {SOURCE_LABELS[individualResult.cve_intelligence.data_source] || individualResult.cve_intelligence.data_source}
                            </span>
                          )}
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 sm:gap-2 text-xs">
                          <div className="flex justify-between py-1">
                            <span className="text-gray-600 dark:text-gray-300">EPSS Score:</span>
                            <span className="font-medium text-gray-900 dark:text-gray-100">{(individualResult.cve_intelligence.epss_score * 100).toFixed(1)}%</span>
                          </div>
                          <div className="flex justify-between py-1">
                            <span className="text-gray-600 dark:text-gray-300">CVSS Score:</span>
                            <span className="font-medium text-gray-900 dark:text-gray-100">{individualResult.cve_intelligence.cvss_score}</span>
                          </div>
                          <div className="flex justify-between py-1">
                            <span className="text-gray-600 dark:text-gray-300">CISA KEV:</span>
                            <span className="font-medium text-gray-900 dark:text-gray-100">{individualResult.cve_intelligence.cisa_kev ? 'Yes' : 'No'}</span>
                          </div>
                          <div className="flex justify-between py-1">
                            <span className="text-gray-600 dark:text-gray-300">Patch Available:</span>
                            <span className="font-medium text-gray-900 dark:text-gray-100">{individualResult.cve_intelligence.patch_available ? 'Yes' : 'No'}</span>
                          </div>
                          {individualResult.cve_intelligence.published_date && (
                            <div className="flex justify-between py-1">
                              <span className="text-gray-600 dark:text-gray-300">Published:</span>
                              <span className="font-medium text-gray-900 dark:text-gray-100">{new Date(individualResult.cve_intelligence.published_date).toLocaleDateString()}</span>
                            </div>
                          )}
                        </div>
                        {individualResult.cve_intelligence.provenance?.degraded_fields?.length > 0 && (
                          <p className="mt-2 text-[11px] text-amber-700 dark:text-amber-300">
                            This source publishes a CVSS base score but no CVSS vector, so attack vector and
                            CIA impact were scored with neutral assumptions rather than measured values.
                          </p>
                        )}
                        {individualResult.calculation_breakdown && (
                          <div className="mt-3 sm:mt-4 p-2 sm:p-3 bg-white dark:bg-gray-800 rounded-lg border border-blue-200 dark:border-blue-700">
                            <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Calculation Breakdown</h4>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 sm:gap-2 text-xs">
                              {Object.entries(individualResult.calculation_breakdown).map(([key, value]) => (
                                <div key={key} className="flex justify-between py-1">
                                  <span className="capitalize text-gray-600 dark:text-gray-300">{key.replace('_', ' ')}:</span>
                                  <span className="font-medium text-gray-900 dark:text-gray-100">{typeof value === 'number' ? value.toFixed(2) : typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {vdrResult && (
                <Card className="bg-gradient-to-r from-purple-100 to-fuchsia-100 dark:from-purple-900/30 dark:to-fuchsia-900/30 border-fuchsia-200 dark:border-fuchsia-700 shadow-lg">
                  <CardHeader className="pb-3 sm:pb-4">
                    <CardTitle className="flex items-center gap-2 text-purple-900 dark:text-purple-100 text-base sm:text-lg lg:text-xl">
                      <CheckCircle className="h-4 w-4 sm:h-5 sm:w-5 lg:h-6 lg:w-6 text-fuchsia-600" />
                      FedRAMP VDR Assessment Complete
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {/* Main metrics */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 lg:gap-6">
                      <div className="text-center">
                        <div className="text-3xl font-bold text-purple-900 mb-2">
                          {vdrResult.impact_rating}
                        </div>
                        <Badge
                          variant="secondary"
                          className={`${getImpactColor(vdrResult.impact_rating)} text-white text-base px-4 py-2`}
                        >
                          {vdrResult.impact_rating} Impact
                        </Badge>
                      </div>
                      <div className="text-center">
                        <div className="text-sm text-gray-600 mb-1">Timeline</div>
                        <div className="text-lg font-semibold text-purple-900 dark:text-purple-900">
                          {vdrResult.timeline.category}
                        </div>
                        <div className="text-sm text-purple-900 dark:text-purple-900">
                          {vdrResult.timeline.days} days
                        </div>
                      </div>
                      <div className="text-center">
                        <div className="text-sm text-gray-600 mb-1">Incident Response</div>
                        <Badge 
                          variant={vdrResult.incident_response_required ? "destructive" : "secondary"}
                          className="bg-purple-100 text-purple-900 dark:bg-purple-100 dark:text-purple-900"
                        >
                          {vdrResult.incident_response_required ? 'Required' : 'Not Required'}
                        </Badge>
                      </div>
                      <div className="text-center">
                        <div className="text-sm text-gray-600 mb-1">CVE ID</div>
                        <div className="text-sm font-mono text-purple-900 dark:text-purple-900">
                          {vdrResult.cve_id}
                        </div>
                      </div>
                    </div>

                    {/* LEV and IRV Decisions */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
                      <div className="p-3 bg-white rounded-lg border border-fuchsia-200">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2">LEV Assessment</h4>
                        <div className="space-y-2">
                          <div className="flex items-center gap-2">
                            <Badge variant={vdrResult.lev.status ? "destructive" : "secondary"}>
                              {vdrResult.lev.status ? 'Likely Exploitable' : 'Not Likely Exploitable'}
                            </Badge>
                          </div>
                          {vdrResult.lev.reasons.length > 0 && (
                            <div>
                              <div className="text-xs font-medium text-gray-600">Reasons:</div>
                              <ul className="text-xs text-gray-600 list-disc list-inside">
                                {vdrResult.lev.reasons.map((reason, idx) => (
                                  <li key={idx}>{reason}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="p-3 bg-white rounded-lg border border-fuchsia-200">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2">IRV Assessment</h4>
                        <div className="space-y-2">
                          <div className="flex items-center gap-2">
                            <Badge variant={vdrResult.irv.status ? "destructive" : "secondary"}>
                              {vdrResult.irv.status ? 'Internet Reachable' : 'Not Internet Reachable'}
                            </Badge>
                          </div>
                          {vdrResult.irv.reasons.length > 0 && (
                            <div>
                              <div className="text-xs font-medium text-gray-600">Reasons:</div>
                              <ul className="text-xs text-gray-600 list-disc list-inside">
                                {vdrResult.irv.reasons.map((reason, idx) => (
                                  <li key={idx}>{reason}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Federal Impact Fields */}
                    {vdrResult.federal_impact_fields && (
                      <div className="mt-4 p-3 bg-white rounded-lg border border-fuchsia-200">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2">Federal Impact Assessment</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                          <div>
                            <span className="font-medium">Service Degradation:</span> {vdrResult.federal_impact_fields.service_degradation_hours}h
                          </div>
                          <div>
                            <span className="font-medium">Data Exposure:</span> {vdrResult.federal_impact_fields.federal_data_exposure_percentage}%
                          </div>
                          <div>
                            <span className="font-medium">Downtime:</span> {vdrResult.federal_impact_fields.estimated_downtime_hours}h
                          </div>
                          <div>
                            <span className="font-medium">Affected Users:</span> {vdrResult.federal_impact_fields.affected_users_percentage}%
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Incident Response Details */}
                    {vdrResult.incident_response && (
                      <div className="mt-4 p-3 bg-white rounded-lg border border-fuchsia-200">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2">Incident Response</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                          <div>
                            <span className="font-medium">Required:</span> {vdrResult.incident_response.required ? 'Yes' : 'No'}
                          </div>
                          {vdrResult.incident_response.incident_id && (
                            <div>
                              <span className="font-medium">Incident ID:</span> {vdrResult.incident_response.incident_id}
                            </div>
                          )}
                          {vdrResult.incident_response.severity && (
                            <div>
                              <span className="font-medium">Severity:</span> {vdrResult.incident_response.severity}
                            </div>
                          )}
                          <div>
                            <span className="font-medium">Federal Notification:</span> {vdrResult.incident_response.federal_notification_required ? 'Required' : 'Not Required'}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Remediation Timeline */}
                    {vdrResult.remediation_timeline && (
                      <div className="mt-4 p-3 bg-white rounded-lg border border-fuchsia-200">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2">Remediation Timeline</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                          <div>
                            <span className="font-medium">Timeline:</span> {vdrResult.remediation_timeline.timeline_days} days
                          </div>
                          <div>
                            <span className="font-medium">Status:</span> {vdrResult.remediation_timeline.status}
                          </div>
                          <div>
                            <span className="font-medium">Days Remaining:</span> {vdrResult.remediation_timeline.days_remaining}
                          </div>
                          <div>
                            <span className="font-medium">Escalation:</span> {vdrResult.remediation_timeline.escalation_required ? 'Required' : 'Not Required'}
                          </div>
                          {vdrResult.remediation_timeline.responsible_team && (
                            <div className="col-span-1 sm:col-span-2">
                              <span className="font-medium">Responsible Team:</span> {vdrResult.remediation_timeline.responsible_team}
                            </div>
                          )}
                          {vdrResult.remediation_timeline.mitigation_actions.length > 0 && (
                            <div className="col-span-1 sm:col-span-2">
                              <span className="font-medium">Mitigation Actions:</span>
                              <ul className="list-disc list-inside mt-1">
                                {vdrResult.remediation_timeline.mitigation_actions.map((action, idx) => (
                                  <li key={idx} className="text-xs">{action}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Assessment Metadata */}
                    <div className="mt-4 p-3 bg-white rounded-lg border border-green-200">
                      <h4 className="text-sm font-semibold text-gray-700 mb-2">Assessment Details</h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                        <div>
                          <span className="font-medium">Authorization Level:</span> {vdrResult.authorization_level}
                        </div>
                        <div>
                          <span className="font-medium">Framework Version:</span> {vdrResult.framework_version}
                        </div>
                        {vdrResult.assessment_timestamp && (
                          <div className="col-span-1 sm:col-span-2">
                            <span className="font-medium">Assessment Time:</span> {new Date(vdrResult.assessment_timestamp).toLocaleString()}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Compliance Report Summary */}
                    {vdrResult.compliance_report && (
                      <div className="mt-4 p-3 bg-white rounded-lg border border-green-200">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2">Compliance Report</h4>
                        <div className="text-xs text-gray-600">
                          <p><strong>Risk Score:</strong> {vdrResult.compliance_report.risk_score}</p>
                          <p><strong>Compliance Status:</strong> {vdrResult.compliance_report.compliance_status}</p>
                          {vdrResult.compliance_report.recommendations && vdrResult.compliance_report.recommendations.length > 0 && (
                            <div className="mt-2">
                              <strong>Recommendations:</strong>
                              <ul className="list-disc list-inside mt-1">
                                {vdrResult.compliance_report.recommendations.map((rec: string, idx: number) => (
                                  <li key={idx}>{rec}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Results Action Buttons */}
              {(individualResult || vdrResult) && (
                <div className="mt-8 p-6 bg-white rounded-lg border border-gray-200 shadow-sm">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4 text-center">Assessment Actions</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                    <Button
                      variant="outline"
                      onClick={() => {
                        setCurrentStep(1);
                        setCveId('');
                        setAssetCriticality(5);
                        setIsInternetFacing(false);
                        setSelectedFramework('enhanced');
                        setIndividualResult(null);
                        setVdrResult(null);
                        setIndividualError(null);
                        setCveIntel({ loading: false, epss: null, cvss: null, kev: null, patchAvailable: null, error: null });
                      }}
                      className="flex items-center justify-center gap-2 py-3 px-4 text-sm font-medium border-2 hover:bg-gray-50 transition-colors"
                    >
                      <Target className="h-4 w-4" />
                      New Assessment
                    </Button>

                    <Button
                      variant="outline"
                      onClick={() => {
                        // Save assessment functionality
                        const assessmentData = individualResult || vdrResult;
                        if (assessmentData) {
                          const dataStr = JSON.stringify(assessmentData, null, 2);
                          const dataBlob = new Blob([dataStr], { type: 'application/json' });
                          const url = URL.createObjectURL(dataBlob);
                          const link = document.createElement('a');
                          link.href = url;
                          link.download = `assessment-${assessmentData.cve_id}-${new Date().toISOString().split('T')[0]}.json`;
                          document.body.appendChild(link);
                          link.click();
                          document.body.removeChild(link);
                          URL.revokeObjectURL(url);
                        }
                      }}
                      className="flex items-center justify-center gap-2 py-3 px-4 text-sm font-medium border-2 hover:bg-gray-50 transition-colors"
                    >
                      <Save className="h-4 w-4" />
                      Save Assessment
                    </Button>

                    <Button
                      onClick={() => {
                        // Download report functionality
                        const assessmentData = individualResult || vdrResult;
                        if (assessmentData) {
                          const reportData = {
                            assessment: assessmentData,
                            timestamp: new Date().toISOString(),
                            type: individualResult ? 'Individual Risk Assessment' : 'FedRAMP VDR Assessment'
                          };
                          const dataStr = JSON.stringify(reportData, null, 2);
                          const dataBlob = new Blob([dataStr], { type: 'application/json' });
                          const url = URL.createObjectURL(dataBlob);
                          const link = document.createElement('a');
                          link.href = url;
                          link.download = `risk-assessment-report-${assessmentData.cve_id}-${new Date().toISOString().split('T')[0]}.json`;
                          document.body.appendChild(link);
                          link.click();
                          document.body.removeChild(link);
                          URL.revokeObjectURL(url);
                        }
                      }}
                      className="flex items-center justify-center gap-2 py-3 px-4 text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white border-2 border-blue-600 hover:border-blue-700 transition-colors"
                    >
                      <Download className="h-4 w-4" />
                      Download Report
                    </Button>

                    <Button
                      variant="outline"
                      onClick={() => {
                        // Share functionality
                        const assessmentData = individualResult || vdrResult;
                        if (assessmentData) {
                          const shareText = `Risk Assessment Results for ${assessmentData.cve_id}\nRisk Score: ${individualResult?.risk_score || 'N/A'}\nPriority: ${individualResult?.priority || vdrResult?.impact_rating || 'N/A'}\nGenerated by VulnRisk`;
                          if (navigator.share) {
                            navigator.share({
                              title: `VulnRisk Assessment - ${assessmentData.cve_id}`,
                              text: shareText,
                              url: window.location.href
                            });
                          } else {
                            // Fallback - copy to clipboard
                            navigator.clipboard.writeText(shareText);
                            // You could add a toast notification here
                          }
                        }
                      }}
                      className="flex items-center justify-center gap-2 py-3 px-4 text-sm font-medium border-2 hover:bg-gray-50 transition-colors"
                    >
                      <Share className="h-4 w-4" />
                      Share Results
                    </Button>
                  </div>
                </div>
              )}

              {/* Usage Guidance */}
              {showGuidance && (
                <Card className="mb-6 bg-gradient-to-r from-blue-50 to-indigo-50 border-blue-200 dark:from-dark-500 dark:to-dark-600 dark:border-blue-700">
                  <CardContent className="p-6">
                    <div className="flex items-start space-x-4">
                      <div className="p-2 bg-blue-100 rounded-full dark:bg-blue-900/30">
                        <Lightbulb className="h-6 w-6 text-blue-600 dark:text-blue-300" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-3">
                          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">How to Use the Risk Calculator</h3>
                          <Button
                            onClick={() => setShowGuidance(false)}
                            className="text-gray-500 hover:text-gray-700 bg-transparent hover:bg-gray-100 dark:text-gray-300 dark:hover:text-white dark:hover:bg-white/10"
                          >
                            <XCircle className="h-4 w-4" />
                          </Button>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm">
                          <div>
                            <h4 className="font-medium text-gray-800 dark:text-gray-100 mb-2">📊 Step 1: Choose Your Framework</h4>
                            <ul className="space-y-1 text-gray-600 dark:text-gray-300">
                              <li>• <strong>Enhanced Contextual:</strong> Fast, minimal inputs for quick triage (Select → Review)</li>
                              <li>• <strong>Mitigation Contextual:</strong> Factor in your deployed controls (Select → Impact & Mitigation → Review)</li>
                              <li>• <strong>Risk Based:</strong> Include environment & reachability (Select → Environment → Review)</li>
                            </ul>
                          </div>
                          <div>
                            <h4 className="font-medium text-gray-800 dark:text-gray-100 mb-2">🎯 Step 2: Rate Your Asset</h4>
                            <ul className="space-y-1 text-gray-600 dark:text-gray-300">
                              <li>• <strong>Level 10:</strong> Mission critical (payment systems)</li>
                              <li>• <strong>Level 8-9:</strong> High impact (customer databases)</li>
                              <li>• <strong>Level 4-5:</strong> Standard ops (dev/test systems)</li>
                              <li>• <strong>Level 1-3:</strong> Low impact (documentation)</li>
                            </ul>
                          </div>
                          <div>
                            <h4 className="font-medium text-gray-800 dark:text-gray-100 mb-2">🔒 Step 3: Add Context (Framework-dependent)</h4>
                            <ul className="space-y-1 text-gray-600 dark:text-gray-300">
                              <li>• <strong>Mitigation Contextual:</strong> List only controls you’ve actually implemented (e.g., WAF, EDR, SIEM)</li>
                              <li>• <strong>Risk Based:</strong> Specify environment & reachability (internet exposure, reach paths, threat intel tags)</li>
                              <li>• Effectiveness varies by CVE traits (network vs. local, privileges, user interaction)</li>
                            </ul>
                          </div>
                          <div>
                            <h4 className="font-medium text-gray-800 dark:text-gray-100 mb-2">📈 Step 4: Interpret Results</h4>
                            <ul className="space-y-1 text-gray-600 dark:text-gray-300">
                              <li>• <strong>CRITICAL (90-100):</strong> Immediate response required</li>
                              <li>• <strong>HIGH (70-89):</strong> Urgent response needed</li>
                              <li>• <strong>MEDIUM (40-69):</strong> Scheduled response</li>
                              <li>• <strong>LOW (20-39):</strong> Standard patching cycle</li>
                            </ul>
                          </div>
                        </div>
                        <div className="mt-4 p-3 bg-white rounded-lg border border-blue-200 dark:bg-dark-600 dark:border-blue-700">
                          <p className="text-sm text-gray-700 dark:text-gray-300">
                            <strong>💡 Pro Tip:</strong> Use the "Show Formula Details" button to understand exactly how your risk score is calculated.
                            All formulas are transparent and auditable.
                          </p>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

        {/* Scoring Guide Section */}
        {showScoringGuide && (
          <Card className="mb-6 bg-gradient-to-r from-purple-50 to-pink-50 border-purple-200 dark:from-dark-500 dark:to-dark-600 dark:border-purple-700">
            <CardContent className="p-6">
              <div className="flex items-start space-x-4">
                <div className="p-2 bg-purple-100 rounded-full">
                  <BarChart3 className="h-6 w-6 text-purple-600" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Risk Score Interpretation Guide</h3>
                    <Button
                      onClick={() => setShowScoringGuide(false)}
                      className="text-gray-500 hover:text-gray-700 bg-transparent hover:bg-gray-100 dark:text-gray-300 dark:hover:text-white dark:hover:bg-white/10"
                    >
                      <XCircle className="h-4 w-4" />
                    </Button>
                  </div>

                  <div className="space-y-4">
                    {/* Score Ranges Table */}
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm border-collapse">
                        <thead>
                          <tr className="border-b-2 border-purple-200 dark:border-purple-700">
                            <th className="text-left p-2 font-semibold text-gray-800 dark:text-gray-100">Score Range</th>
                            <th className="text-left p-2 font-semibold text-gray-800 dark:text-gray-100">Priority</th>
                            <th className="text-left p-2 font-semibold text-gray-800 dark:text-gray-100">Timeline</th>
                            <th className="text-left p-2 font-semibold text-gray-800 dark:text-gray-100">Real-World Meaning</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr className="border-b border-gray-200 bg-red-50 dark:border-gray-700 dark:bg-red-900/20">
                            <td className="p-2 font-mono text-red-800 dark:text-red-300">≥ 90</td>
                            <td className="p-2">
                              <Badge className="bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-200 dark:border-red-700">CRITICAL</Badge>
                            </td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">7 days (base)</td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">Emergency response window; immediate risk to business</td>
                          </tr>
                          <tr className="border-b border-gray-200 bg-orange-50 dark:border-gray-700 dark:bg-orange-900/20">
                            <td className="p-2 font-mono text-orange-800 dark:text-orange-300">70–89</td>
                            <td className="p-2">
                              <Badge className="bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/30 dark:text-orange-200 dark:border-orange-700">HIGH</Badge>
                            </td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">30 days (base)</td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">Serious threats; prioritize this sprint/month</td>
                          </tr>
                          <tr className="border-b border-gray-200 bg-yellow-50 dark:border-gray-700 dark:bg-yellow-900/10">
                            <td className="p-2 font-mono text-yellow-800 dark:text-yellow-200">40–69</td>
                            <td className="p-2">
                              <Badge className="bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/20 dark:text-yellow-200 dark:border-yellow-700">MEDIUM</Badge>
                            </td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">60 days (base)</td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">Significant risk; plan within quarter</td>
                          </tr>
                          <tr className="border-b border-gray-200 bg-blue-50 dark:border-gray-700 dark:bg-blue-900/20">
                            <td className="p-2 font-mono text-blue-800 dark:text-blue-300">20–39</td>
                            <td className="p-2">
                              <Badge className="bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/30 dark:text-blue-200 dark:border-blue-700">LOW</Badge>
                            </td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">120 days (base)</td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">Lower priority; standard maintenance</td>
                          </tr>
                          <tr className="border-b border-gray-200 bg-gray-50 dark:border-gray-700 dark:bg-gray-800/30">
                            <td className="p-2 font-mono text-gray-600 dark:text-gray-300">&lt; 20</td>
                            <td className="p-2">
                              <Badge className="bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-700 dark:text-gray-100 dark:border-gray-600">INFORMATIONAL</Badge>
                            </td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">Next maintenance window</td>
                            <td className="p-2 text-gray-700 dark:text-gray-300">Track/monitor; negligible business impact</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    {/* Key Points */}
                    <div className="mt-4">
                      <div className="bg-white p-4 rounded-lg border border-purple-200 dark:bg-dark-600 dark:border-purple-700">
                        <h4 className="font-semibold text-gray-800 dark:text-gray-100 mb-2">📊 Timeline Accelerators (apply to base timeline)</h4>
                        <ul className="text-sm text-gray-600 dark:text-gray-300 space-y-1">
                          <li>• CISA KEV: cap at 14 days</li>
                          <li>• Active exploitation: halve timeline (minimum 3 days)</li>
                          <li>• High asset criticality: ~30% faster (minimum 5 days)</li>
                          <li>• Internet‑reachable exposure: additional acceleration</li>
                          <li>• Accelerators adjust days; labels don’t change unless the score changes</li>
                        </ul>
                      </div>
                    </div>

                    {/* Optional compact FedRAMP VDR matrix */}
                    <div className="mt-4">
                      <Button
                        onClick={() => setShowVdrMatrix(!showVdrMatrix)}
                        className="bg-green-600 hover:bg-green-700 text-white px-3 py-2 text-sm"
                      >
                        {showVdrMatrix ? 'Hide FedRAMP VDR Quick Reference' : 'Show FedRAMP VDR Quick Reference'}
                      </Button>
                      {showVdrMatrix && (
                        <div className="mt-3 bg-white p-4 rounded-lg border border-green-200 dark:bg-dark-600 dark:border-green-700">
                          <div className="flex items-center justify-between mb-2">
                            <div className="text-sm font-semibold text-gray-800 dark:text-gray-100">Authorization Timelines</div>
                            <div className="flex items-center gap-2">
                              <label className="text-xs text-gray-600 dark:text-gray-300">Impact Level:</label>
                              <select
                                aria-label="FedRAMP authorization level"
                                value={vdrAuthLevel}
                                onChange={(e) => setVdrAuthLevel(e.target.value as any)}
                                className="text-xs border border-gray-300 rounded px-2 py-1 dark:bg-dark-500 dark:border-gray-600"
                              >
                                <option value="low">Low</option>
                                <option value="moderate">Moderate</option>
                                <option value="high">High</option>
                              </select>
                            </div>
                          </div>
                          <div className="overflow-x-auto">
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="border-b-2 border-green-200">
                                  <th className="text-left p-2 font-semibold text-gray-800">Impact</th>
                                  <th className="text-left p-2 font-semibold text-gray-800">LEV+IRV</th>
                                  <th className="text-left p-2 font-semibold text-gray-800">LEV+NIRV</th>
                                  <th className="text-left p-2 font-semibold text-gray-800">NLEV</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(
                                  vdrAuthLevel === 'low' ? [
                                    ['N5','4','8','32'],
                                    ['N4','8','32','64'],
                                    ['N3','32','64','192'],
                                    ['N2','96','160','192'],
                                  ] : vdrAuthLevel === 'moderate' ? [
                                    ['N5','2','4','16'],
                                    ['N4','4','8','64'],
                                    ['N3','16','32','128'],
                                    ['N2','48','128','192'],
                                  ] : [
                                    ['N5','0.5','1','8'],
                                    ['N4','2','8','32'],
                                    ['N3','8','16','64'],
                                    ['N2','24','96','192'],
                                  ]
                                ).map((row) => (
                                  <tr key={row[0]} className="border-b border-gray-200">
                                    <td className="p-2 font-mono text-gray-800 font-semibold">{row[0]}</td>
                                    <td className="p-2 text-gray-700">{row[1]}</td>
                                    <td className="p-2 text-gray-700">{row[2]}</td>
                                    <td className="p-2 text-gray-700">{row[3]}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          <div className="text-[11px] text-gray-600 mt-2">VDR uses N1–N5 impact ratings and LEV/IRV status; no numeric risk scores.</div>
                          <details className="mt-3">
                            <summary className="cursor-pointer text-xs font-semibold text-gray-800">Key inputs & examples</summary>
                            <div className="mt-2 text-[11px] text-gray-700 space-y-2">
                              <div>
                                <div className="font-semibold">Impact rating (N1–N5)</div>
                                <ul className="list-disc ml-4 space-y-1">
                                  <li><span className="font-medium">N2 – Limited:</span> small data exposure (&lt;10%) or few users affected (&lt;10%). Example: 5% federal data in a single dataset.</li>
                                  <li><span className="font-medium">N3 – Serious:</span> meaningful exposure (10–49%) or notable user impact (≥10%). Example: 15% of users impacted; 25% federal data.</li>
                                  <li><span className="font-medium">N4 – High/Critical:</span> 12+ hours degradation or serious effect on multiple agencies. Example: 18h downtime for an agency‑facing service.</li>
                                  <li><span className="font-medium">N5 – Catastrophic:</span> 24+ hours service loss or majority (≥50%) federal data exposure.</li>
                                </ul>
                              </div>
                              <div>
                                <div className="font-semibold">LEV (Likely Exploitable)</div>
                                <ul className="list-disc ml-4 space-y-1">
                                  <li>Not fully mitigated + reachable + exploitation likely (e.g., KEV listed or EPSS high).</li>
                                  <li>Example: KEV listed vuln reachable via a partner API → LEV = true.</li>
                                </ul>
                              </div>
                              <div>
                                <div className="font-semibold">IRV (Internet‑Reachable)</div>
                                <ul className="list-disc ml-4 space-y-1">
                                  <li>Triggerable by internet‑originated payloads (not just network open ports).</li>
                                  <li>Example: backend parser processing files uploaded from the web.</li>
                                </ul>
                              </div>
                              <div>
                                <div className="font-semibold">Authorization level (Low / Moderate / High)</div>
                                <ul className="list-disc ml-4 space-y-1">
                                  <li><span className="font-medium">Low:</span> longer windows (e.g., N3 NLEV 192d).</li>
                                  <li><span className="font-medium">Moderate:</span> balanced windows (e.g., N3 LEV+NIRV 32d).</li>
                                  <li><span className="font-medium">High:</span> shortest windows (e.g., N5 LEV+IRV 0.5d).</li>
                                </ul>
                              </div>
                            </div>
                          </details>
                        </div>
                      )}
                    </div>

                    <div className="mt-4 p-3 bg-white rounded-lg border border-purple-200">
                      <p className="text-sm text-gray-700">
                        <strong>💡 Pro Tip:</strong> The Risk Based framework uses the complete master formula and the same
                        priority bands, with richer context/threat/mitigation multipliers for more explainability.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Show Guidance Button */}
        {!showGuidance && !showScoringGuide && (
          <div className="mb-3 sm:mb-4 text-center flex flex-col sm:flex-row gap-2 sm:gap-3 sm:justify-center">
            <Button
              onClick={() => setShowGuidance(true)}
              className="text-blue-700 border-2 border-blue-300 hover:bg-blue-50 bg-blue-50 font-semibold px-3 sm:px-4 py-2 text-sm rounded-lg transition-colors order-1 sm:order-1 dark:text-blue-300 dark:bg-blue-900/20 dark:hover:bg-blue-900/30 dark:border-blue-700"
            >
              <Lightbulb className="h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2" />
              <span className="hidden sm:inline">Show Usage Guide</span>
              <span className="sm:hidden">Usage Guide</span>
            </Button>
            <Button
              onClick={() => setShowScoringGuide(true)}
              className="bg-gray-600 hover:bg-gray-700 text-white border-2 border-gray-500 hover:border-gray-600 font-semibold px-3 sm:px-4 py-2 text-sm rounded-lg transition-colors order-2 sm:order-2 dark:bg-primary-700 dark:hover:bg-primary-600 dark:border-primary-600 dark:hover:border-primary-500"
            >
              <BarChart3 className="h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2" />
              <span className="hidden sm:inline">Show Scoring Guide</span>
              <span className="sm:hidden">Scoring Guide</span>
            </Button>
          </div>
        )}

              {/* Step 1: Framework & CVE Selection */}
              {currentStep === 1 && (
                <div className="space-y-3 sm:space-y-4 lg:space-y-5">
                  <Card className="w-full">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Target className="h-5 w-5" />
                        Framework Selection
                      </CardTitle>
                      <CardDescription>
                        Choose the appropriate assessment framework for your requirements
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 lg:gap-4 w-full">
                        {[
                          {
                            value: "enhanced",
                            title: "Enhanced Contextual",
                            description: "Fast, business-aligned risk scoring with real vulnerability data",
                            recommended: false,
                          },
                          {
                            value: "mitigation-contextual",
                            title: "Mitigation Contextual",
                            description: "Factors in existing security controls and mitigation measures",
                            recommended: false,
                          },
                          {
                            value: "risk-based",
                            title: "Risk Based",
                            description: "Pure risk calculation based on threat landscape and asset value",
                            recommended: true,
                          },
                          {
                            value: "fedramp-vdr",
                            title: "FedRAMP VDR",
                            description: "Federal compliance assessment with N1-N5 impact classification",
                            recommended: false,
                          },
                        ].map((tile) => (
                          <div
                            key={tile.value}
                            className={`relative p-3 lg:p-4 border rounded-lg cursor-pointer transition-all hover:border-blue-300 min-w-0 ${
                              selectedFramework === tile.value
                                ? "border-blue-500 bg-blue-50 dark:border-primary-400 dark:bg-primary-900/20"
                                : "border-gray-200 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-800"
                            }`}
                            onClick={() => setSelectedFramework(tile.value as any)}
                          >
                            {tile.recommended && (
                              <Badge className="absolute -top-2 -right-2 bg-green-500">
                                Recommended
                              </Badge>
                            )}
                            <div className="font-medium mb-2 break-words dark:text-white">
                              {tile.title}
                            </div>
                            <div className="text-sm text-gray-600 break-words dark:text-gray-300">
                              {tile.description}
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="w-full">
                    <CardHeader>
                      <CardTitle>CVE & Context</CardTitle>
                      <CardDescription>
                        Enter the CVE ID to auto-fetch vulnerability data and set context
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3 lg:space-y-4 w-full">
                      {/* CVE Input */}
                      <div>
                        <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-white-300">CVE ID *</label>
                        <div className="flex gap-2">
                          <Input
                            value={cveId}
                            onChange={(e) => {
                              setCveId(e.target.value);
                              if (cveIdError) setCveIdError('');
                            }}
                            onBlur={(e) => {
                              const value = e.target.value;
                              if (value.trim() && !isValidCveId(value)) {
                                setCveIdError('Please enter a valid CVE ID (e.g., CVE-2025-1234)');
                              }
                              fetchCveIntel(value);
                            }}
                            placeholder="CVE-2025-1234"
                            className={`flex-1 ${cveIdError ? 'border-red-500 focus:border-red-500 focus:ring-red-200' : ''}`}
                          />
                          <Button
                            variant="outline"
                            onClick={() => fetchCveIntel(cveId)}
                            disabled={!cveId || cveIntel.loading || !!cveIdError}
                          >
                            Auto-fetch
                          </Button>
                        </div>
                        {cveIdError && (
                          <p className="text-sm text-red-600 mt-1">{cveIdError}</p>
                        )}
                      </div>

                      {/* Data Chips */}
                      {cveId && (
                        <div className="w-full">
                          <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Vulnerability Data</label>
                          <div className="flex flex-wrap gap-3 w-full">
                            <DataChip
                              variant="epss"
                              state={
                                cveIntel.loading
                                  ? "loading"
                                  : cveIntel.epss !== null
                                    ? "ok"
                                    : "error"
                              }
                              value={
                                cveIntel.epss !== null
                                  ? `${(cveIntel.epss * 100).toFixed(1)}%`
                                  : undefined
                              }
                              subtitle="exploitation probability"
                            />
                            <DataChip
                              variant="cvss"
                              state={
                                cveIntel.loading
                                  ? "loading"
                                  : cveIntel.cvss !== null
                                    ? "ok"
                                    : "error"
                              }
                              value={
                                cveIntel.cvss !== null
                                  ? cveIntel.cvss.toFixed(1)
                                  : undefined
                              }
                              subtitle="base score"
                            />
                            <DataChip
                              variant="kev"
                              state={
                                cveIntel.loading
                                  ? "loading"
                                  : cveIntel.kev !== null
                                    ? "ok"
                                    : "error"
                              }
                              value={
                                cveIntel.kev
                                  ? "Listed"
                                  : "Not Listed"
                              }
                              subtitle="CISA known exploited"
                            />
                            <DataChip
                              variant="patch"
                              state={
                                cveIntel.loading
                                  ? "loading"
                                  : cveIntel.patchAvailable !== null
                                    ? "ok"
                                    : "error"
                              }
                              value={
                                cveIntel.patchAvailable
                                  ? "Available"
                                  : "Not Available"
                              }
                              subtitle="vendor patch status"
                            />
                          </div>
                        </div>
                      )}

                      {/* Context Fields */}
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 lg:gap-4 w-full">
                        {selectedFramework === 'fedramp-vdr' ? (
                          <>
                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Authorization Level *</label>
                              <select
                                value={vdrInputs.authorization_level}
                                onChange={(e) => setVdrInputs(prev => ({ ...prev, authorization_level: e.target.value }))}
                                className="w-full p-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 min-w-0"
                                aria-label="Authorization Level"
                                title="Select authorization level for assessment"
                              >
                                <option value="">Select level</option>
                                <option value="low">Low</option>
                                <option value="moderate">Moderate</option>
                                <option value="high">High</option>
                              </select>
                              <div className="text-xs text-gray-500 mt-1">
                                Authorization impact levels determines remediation timeline.
                              </div>
                            </div>

                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Asset Criticality Rating *</label>
                              <select
                                value={vdrInputs.asset_criticality_rating}
                                onChange={(e) => setVdrInputs(prev => ({ ...prev, asset_criticality_rating: e.target.value }))}
                                className="w-full p-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 min-w-0"
                                aria-label="Asset Criticality Rating"
                                title="Select asset criticality rating"
                              >
                                <option value="">Select rating</option>
                                <option value="low">Low - Development/test systems</option>
                                <option value="medium">Medium - Standard business operations</option>
                                <option value="high">High - Critical business systems</option>
                                <option value="mission_critical">Mission Critical - Essential infrastructure</option>
                              </select>
                              <div className="text-xs text-gray-500 mt-1">
                                Mission importance assessment for federal impact classification
                              </div>
                            </div>
                          </>
                        ) : (
                          <>
                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                                Asset Criticality: {assetCriticality}
                              </label>
                              <input
                                type="range"
                                min="1"
                                max="10"
                                value={assetCriticality}
                                onChange={(e) => setAssetCriticality(parseInt(e.target.value))}
                                className="w-full"
                                aria-label="Asset Criticality Level"
                                title="Asset Criticality Level (1-10)"
                              />
                              <div className="flex justify-between text-xs text-gray-500 mt-1">
                                <span>Low (1)</span>
                                <span>Standard (5)</span>
                                <span>Critical (10)</span>
                              </div>
                            </div>

                            <div className="flex items-center justify-between">
                              <div>
                                <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Internet Facing</label>
                                <div className="text-sm text-gray-600">
                                  Asset accessible from internet
                                </div>
                              </div>
                              <input
                                type="checkbox"
                                checked={isInternetFacing}
                                onChange={(e) => setIsInternetFacing(e.target.checked)}
                                className="rounded"
                                aria-label="Asset is Internet Facing"
                                title="Asset is Internet Facing"
                              />
                            </div>
                          </>
                        )}
                      </div>
                    </CardContent>
                  </Card>

                  <div className="flex justify-end">
                    {(() => {
                      const nextId = getNextVisibleStepId(selectedFramework, 1);
                      if (!nextId) {
                        // Last step (e.g., Enhanced) → show Calculate here
                        return (
                          <Button onClick={calculateIndividualRisk} disabled={!canCalculate()}>
                            Calculate
                            <ChevronRight className="ml-2 h-4 w-4" />
                          </Button>
                        );
                      }
                      const nextLabel = nextId === 2 ? 'Next: Impact & Mitigation' : nextId === 3 ? 'Next: Environment' : 'Review & Calculate';
                      const disabled = (nextId === 2 && !canProceedToStep2()) || (nextId > maxStepForFramework(selectedFramework));
                      return (
                        <Button onClick={nextStep} disabled={disabled}>
                          {nextLabel}
                          <ChevronRight className="ml-2 h-4 w-4" />
                        </Button>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* Step 2: Impact & Mitigation */}
              {currentStep === 2 && (selectedFramework === 'mitigation-contextual' || selectedFramework === 'fedramp-vdr' || selectedFramework === 'risk-based') && (
                <div className="space-y-3 sm:space-y-4 lg:space-y-5">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Settings className="h-5 w-5" />
                        Mitigation Assessment
                      </CardTitle>
                      <CardDescription>
                        Current mitigation status and effectiveness
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                      {selectedFramework === 'fedramp-vdr' ? (
                        <>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Current Mitigation Level</label>
                              <select
                                value={vdrInputs.current_mitigation_level}
                                onChange={(e) => setVdrInputs(prev => ({ ...prev, current_mitigation_level: e.target.value }))}
                                className="w-full p-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                                aria-label="Current Mitigation Level"
                                title="Select current mitigation level"
                              >
                                <option value="none">None - No mitigations in place</option>
                                <option value="partial">Partial - Some compensating controls</option>
                                <option value="full">Full - Comprehensive controls implemented</option>
                              </select>
                              <div className="text-xs text-gray-500 mt-1">
                                Current level of mitigation implementation per FRD-ALL-43
                              </div>
                            </div>

                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                                Mitigation Effectiveness: {(vdrInputs.mitigation_effectiveness * 100).toFixed(0)}%
                              </label>
                              <input
                                type="range"
                                min="0"
                                max="1"
                                step="0.1"
                                value={vdrInputs.mitigation_effectiveness}
                                onChange={(e) => setVdrInputs(prev => ({ ...prev, mitigation_effectiveness: parseFloat(e.target.value) }))}
                                className="w-full"
                                aria-label="Mitigation Effectiveness"
                                title="Mitigation Effectiveness (0-100%)"
                              />
                              <div className="flex justify-between text-xs text-gray-500 mt-1">
                                <span>Ineffective (0%)</span>
                                <span>Highly Effective (100%)</span>
                              </div>
                            </div>
                          </div>

                          {vdrInputs.current_mitigation_level !== 'none' && (
                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Compensating Controls</label>
                              <textarea
                                placeholder="List implemented controls (e.g., Web Application Firewall (WAF), Network Segmentation, Enhanced Monitoring)"
                                value={vdrInputs.compensating_controls.join('\n')}
                                onChange={(e) => setVdrInputs(prev => ({
                                  ...prev,
                                  compensating_controls: e.target.value.split('\n').filter(Boolean)
                                }))}
                                className="w-full p-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                                rows={3}
                              />
                            </div>
                          )}
                        </>
                      ) : (
                        <>
                          {/* Explicit controls (required for non-VDR) */}
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Preventive Controls</label>
                              <textarea
                                placeholder="e.g., WAF, Network Segmentation, MFA on Admin"
                                value={mitigationControls.preventive_controls.join('\n')}
                                onChange={(e) => setMitigationControls(prev => ({
                                  ...prev,
                                  preventive_controls: e.target.value.split('\n').filter(Boolean)
                                }))}
                                className="w-full p-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                                rows={3}
                              />
                            </div>
                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Detective Controls</label>
                              <textarea
                                placeholder="e.g., SIEM use cases, EDR coverage, Alerting"
                                value={mitigationControls.detective_controls.join('\n')}
                                onChange={(e) => setMitigationControls(prev => ({
                                  ...prev,
                                  detective_controls: e.target.value.split('\n').filter(Boolean)
                                }))}
                                className="w-full p-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                                rows={3}
                              />
                            </div>
                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Response Controls</label>
                              <textarea
                                placeholder="e.g., Playbooks, Containment steps, Patching SLAs"
                                value={mitigationControls.response_controls.join('\n')}
                                onChange={(e) => setMitigationControls(prev => ({
                                  ...prev,
                                  response_controls: e.target.value.split('\n').filter(Boolean)
                                }))}
                                className="w-full p-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                                rows={3}
                              />
                            </div>
                          </div>
                        </>
                      )}
                    </CardContent>
                  </Card>

                  {selectedFramework === 'fedramp-vdr' && (
                    <Card>
                      <CardHeader>
                        <CardTitle>Federal Impact Assessment</CardTitle>
                        <CardDescription>
                          Service impact and federal data exposure assessment
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          <div>
                            <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Service Degradation (hours)</label>
                            <Input
                              type="number"
                              placeholder="0.0"
                              value={vdrInputs.service_degradation_hours || ''}
                              onChange={(e) => setVdrInputs(prev => ({
                                ...prev,
                                service_degradation_hours: parseFloat(e.target.value) || 0
                              }))}
                              className="w-full"
                              step="0.1"
                              min="0"
                            />
                            <div className="text-xs text-gray-500 mt-1">
                              Estimated service degradation in hours (0-168)
                            </div>
                          </div>

                          <div>
                            <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Estimated Downtime (hours)</label>
                            <Input
                              type="number"
                              placeholder="0.0"
                              value={vdrInputs.estimated_downtime_hours || ''}
                              onChange={(e) => setVdrInputs(prev => ({
                                ...prev,
                                estimated_downtime_hours: parseFloat(e.target.value) || 0
                              }))}
                              className="w-full"
                              step="0.1"
                              min="0"
                            />
                            <div className="text-xs text-gray-500 mt-1">
                              Estimated downtime in hours (0-168)
                            </div>
                          </div>

                          <div>
                            <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                              Federal Data Exposure: {vdrInputs.federal_data_exposure_percentage}%
                            </label>
                            <input
                              type="range"
                              min="0"
                              max="100"
                              step="5"
                              value={vdrInputs.federal_data_exposure_percentage}
                              onChange={(e) => setVdrInputs(prev => ({
                                ...prev,
                                federal_data_exposure_percentage: parseInt(e.target.value)
                              }))}
                              className="w-full"
                              aria-label="Federal Data Exposure"
                              title="Federal Data Exposure (0-100%)"
                            />
                            <div className="text-xs text-gray-500 mt-1">
                              Percentage of affected data that is federal (0-100%)
                            </div>
                          </div>

                          <div className="flex items-center justify-between">
                            <div>
                              <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Contains Federal Data</label>
                              <div className="text-sm text-gray-600">
                                Asset contains federal/sensitive data
                              </div>
                            </div>
                            <input
                              type="checkbox"
                              checked={vdrInputs.asset_contains_federal_data}
                              onChange={(e) => setVdrInputs(prev => ({ ...prev, asset_contains_federal_data: e.target.checked }))}
                              className="rounded"
                              aria-label="Asset Contains Federal Data"
                              title="Asset Contains Federal Data"
                            />
                          </div>

                          <div>
                            <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                              Affected Users: {vdrInputs.affected_users_percentage}%
                            </label>
                            <input
                              type="range"
                              min="0"
                              max="100"
                              step="5"
                              value={vdrInputs.affected_users_percentage}
                              onChange={(e) => setVdrInputs(prev => ({
                                ...prev,
                                affected_users_percentage: parseInt(e.target.value)
                              }))}
                              className="w-full"
                              aria-label="Affected Users Percentage"
                              title="Affected Users Percentage (0-100%)"
                            />
                            <div className="text-xs text-gray-500 mt-1">
                              Percentage of users affected (0-100%)
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  )}

                  <div className="flex justify-between">
                    <Button variant="outline" onClick={prevStep}>
                      <ChevronLeft className="mr-2 h-4 w-4" />
                      Back
                    </Button>
                    {(() => {
                      const nextId = getNextVisibleStepId(selectedFramework, 2);
                      if (!nextId) {
                        return (
                          <Button onClick={calculateIndividualRisk} disabled={!canCalculate()}>
                            Calculate
                            <ChevronRight className="ml-2 h-4 w-4" />
                          </Button>
                        );
                      }
                      const nextLabel = nextId === 3 ? 'Next: Environment' : 'Review & Calculate';
                      return (
                        <Button onClick={nextStep}>
                          {nextLabel}
                          <ChevronRight className="ml-2 h-4 w-4" />
                        </Button>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* Step 3: Environment & Reachability */}
              {currentStep === 3 && (selectedFramework === 'risk-based' || selectedFramework === 'fedramp-vdr') && (
                <div className="space-y-3 sm:space-y-4 lg:space-y-5">
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Network className="h-5 w-5" />
                        Environment & Reachability
                      </CardTitle>
                      <CardDescription>
                        Network context and threat intelligence
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">
                      {selectedFramework === 'fedramp-vdr' && (
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="flex items-center gap-2">
                              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Internet Reachable</label>
                              <details className="group">
                                <summary className="cursor-pointer inline-flex items-center gap-1 text-xs bg-green-50 text-green-700 border border-green-200 rounded px-2 py-1 hover:bg-green-100 transition-colors">
                                  <span className="font-semibold">IRV?</span>
                                </summary>
                                <div className="mt-3 p-3 sm:p-4 bg-white border border-green-200 rounded-lg shadow-sm max-w-xl">
                                  <div className="text-[11px] sm:text-xs text-gray-700 space-y-3">
                                    <div className="flex items-center gap-2">
                                      <div className="text-[10px] font-semibold text-green-700 bg-green-50 border border-green-200 px-2 py-0.5 rounded">FRD-ALL-24</div>
                                      <div className="font-semibold">Internet-reachable Vulnerability (IRV)</div>
                                    </div>
                                    <p className="leading-5">
                                      A vulnerability in a machine-based information resource that might be exploited or otherwise triggered by a payload originating from the public internet; this includes resources with no direct route to/from the internet that still receive payloads or take action triggered by internet activity.
                                    </p>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                      <div className="bg-green-50 border border-green-200 rounded-md p-2">
                                        <div className="text-[11px] font-semibold text-green-800 mb-1">Notes</div>
                                        <ul className="list-disc ml-4 space-y-1">
                                          <li>The opposite is <em>NIRV</em> (Not Internet‑reachable Vulnerability).</li>
                                          <li>IRV applies only to the vulnerable resource processing the payload.</li>
                                        </ul>
                                      </div>
                                      <div className="bg-gray-50 border border-gray-200 rounded-md p-2">
                                        <div className="text-[11px] font-semibold text-gray-800 mb-1">Examples</div>
                                        <ul className="list-disc ml-4 space-y-1">
                                          <li>Backend service parsing user uploads from a web app.</li>
                                          <li>Message processor handling internet-originated queue events.</li>
                                        </ul>
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              </details>
                            </div>
                            <div className="text-sm text-gray-600">Asset reachable from internet</div>
                          </div>
                          <input
                            type="checkbox"
                            checked={vdrInputs.internet_reachable}
                            onChange={(e) => setVdrInputs(prev => ({ ...prev, internet_reachable: e.target.checked }))}
                            className="rounded"
                            aria-label="Asset is Internet Reachable"
                            title="Asset is Internet Reachable"
                          />
                        </div>
                      )}

                      <div>
                        <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Reachability Paths</label>
                        <textarea
                          placeholder="Enter reachability paths (one per line): Direct Internet, VPN Access, Internal Network, DMZ"
                          value={vdrInputs.reachability_paths.join('\n')}
                          onChange={(e) => setVdrInputs(prev => ({
                            ...prev,
                            reachability_paths: e.target.value.split('\n').filter(Boolean)
                          }))}
                          className="w-full p-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                          rows={3}
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Threat Intelligence Tags</label>
                        <textarea
                          placeholder="Enter threat intel tags (one per line): APT Groups, Ransomware, Nation State, Cybercriminal"
                          value={vdrInputs.threat_intel_tags.join('\n')}
                          onChange={(e) => setVdrInputs(prev => ({
                            ...prev,
                            threat_intel_tags: e.target.value.split('\n').filter(Boolean)
                          }))}
                          className="w-full p-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                          rows={3}
                        />
                      </div>
                    </CardContent>
                  </Card>

                  <div className="flex justify-between">
                    <Button variant="outline" onClick={prevStep}>
                      <ChevronLeft className="mr-2 h-4 w-4" />
                      Back
                    </Button>
                    {(() => {
                      const nextId = getNextVisibleStepId(selectedFramework, 3);
                      if (!nextId) {
                        return (
                          <Button onClick={calculateIndividualRisk} disabled={!canCalculate()}>
                            Calculate
                            <ChevronRight className="ml-2 h-4 w-4" />
                          </Button>
                        );
                      }
                      return (
                        <Button onClick={nextStep}>
                          Review & Calculate
                          <ChevronRight className="ml-2 h-4 w-4" />
                        </Button>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* Step 4: Results - Hidden since results are shown immediately */}
              {currentStep === 4 && !individualResult && !vdrResult && (
                <div className="space-y-6">
                  {isCalculating ? (
                    <Card>
                      <CardContent className="text-center py-12">
                        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                        <h3 className="text-lg font-medium text-gray-900 mb-2">Calculating Risk Score</h3>
                        <p className="text-gray-600">Please wait while we process your assessment...</p>
                      </CardContent>
                    </Card>
                  ) : (
                    <Card>
                      <CardContent className="text-center py-12">
                        <div className="text-4xl mb-4">📊</div>
                        <h3 className="text-lg font-medium text-gray-900 mb-2">Ready to Calculate</h3>
                        <p className="text-gray-600 mb-4">
                          Use the "Review & Calculate" button in the right panel to get your risk assessment results.
                        </p>
                        <Button
                          onClick={() => setCurrentStep(1)}
                          variant="outline"
                        >
                          Start New Assessment
                        </Button>
                      </CardContent>
                    </Card>
                  )}
                </div>
              )}

            </div>
          </div>

          {/* Mobile version of SummaryRail - appears at bottom on mobile */}
          <div className="lg:hidden mt-3 sm:mt-4 lg:mt-6 space-y-1 sm:space-y-2 lg:space-y-3">
            <SummaryRail
              selectedFramework={selectedFramework}
              cveId={cveId}
              assetCriticality={assetCriticality}
              authorizationLevel={vdrInputs.authorization_level}
              assetCriticalityRating={vdrInputs.asset_criticality_rating}
              autoPopulatedData={{
                epss: cveIntel.epss ?? undefined,
                cvss: cveIntel.cvss ?? undefined,
                kev: cveIntel.kev ?? undefined,
                patchAvailable: cveIntel.patchAvailable ?? undefined,
              }}
              impactData={{
                mitigation_level: vdrInputs.current_mitigation_level,
                mitigation_effectiveness: vdrInputs.mitigation_effectiveness,
                federal_data_exposure: vdrInputs.federal_data_exposure_percentage,
                affected_users: vdrInputs.affected_users_percentage,
              }}
              environmentData={{
                reachability_paths: vdrInputs.reachability_paths,
                threat_intel_tags: vdrInputs.threat_intel_tags,
                internet_reachable: vdrInputs.internet_reachable || isInternetFacing,
              }}
              warnings={computeWarnings()}
              onCalculate={calculateIndividualRisk}
              isLoading={isCalculating}
              canCalculate={canCalculate()}
            />
          </div>
        </TabsContent>

        {/* Right-side panel - Compact sidebar */}
        <div className="hidden lg:block fixed top-16 right-1 xl:right-2 2xl:right-2 z-40 w-72 xl:w-72 2xl:w-72 h-[calc(100vh-6rem)]">
          <div className="bg-white/95 dark:bg-gray-800/95 shadow-lg border border-gray-200/80 dark:border-gray-700/80 h-full flex flex-col">
            <div className="flex-1 overflow-y-auto p-4 space-y-2 scrollbar-thin scrollbar-thumb-gray-300 scrollbar-track-gray-100">
          <SummaryRail
            selectedFramework={selectedFramework}
            cveId={cveId}
            assetCriticality={assetCriticality}
            authorizationLevel={vdrInputs.authorization_level}
            assetCriticalityRating={vdrInputs.asset_criticality_rating}
            autoPopulatedData={{
              epss: cveIntel.epss ?? undefined,
              cvss: cveIntel.cvss ?? undefined,
              kev: cveIntel.kev ?? undefined,
              patchAvailable: cveIntel.patchAvailable ?? undefined,
            }}
            impactData={{
              mitigation_level: vdrInputs.current_mitigation_level,
              mitigation_effectiveness: vdrInputs.mitigation_effectiveness,
              federal_data_exposure: vdrInputs.federal_data_exposure_percentage,
              affected_users: vdrInputs.affected_users_percentage,
            }}
            controlsSummary={{
              preventive: mitigationControls.preventive_controls.length,
              detective: mitigationControls.detective_controls.length,
              response: mitigationControls.response_controls.length,
            }}
            environmentData={{
              reachability_paths: vdrInputs.reachability_paths,
              threat_intel_tags: vdrInputs.threat_intel_tags,
              internet_reachable: vdrInputs.internet_reachable || isInternetFacing,
            }}
            warnings={computeWarnings()}
            onCalculate={calculateIndividualRisk}
            isLoading={isCalculating}
            canCalculate={canCalculate()}
          />
            </div>
          </div>
        </div>

        {/* Batch Processing Tab */}
        <TabsContent value="batch" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Batch Risk Assessment</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Demo Banner */}
              <div className="bg-indigo-50 border border-indigo-200 rounded-lg p-4">
                <div className="flex items-start space-x-3">
                  <div className="flex-shrink-0">
                    <BarChart3 className="h-5 w-5 text-indigo-600" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <h3 className="text-sm font-medium text-indigo-900">Batch Processing Demo</h3>
                      <Badge variant="secondary">Demo</Badge>
                    </div>
                    <p className="text-sm text-indigo-700 mb-2">
                      This feature is not complete and just for demo purposes. Not real data yet.
                    </p>
                  </div>
                </div>
              </div>

              <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
                <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                  Upload CSV File
                </h3>
                <p className="text-sm text-gray-600 mb-4">
                  CSV should include columns: cve_id, asset_criticality, framework, is_internet_facing (optional)
                </p>
                <Button variant="outline">Choose File</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Results History Tab */}
        <TabsContent value="results" className="space-y-6">
          <Card>
            <CardContent className="text-center py-12">
              <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                Results History
              </h3>
              <p className="text-gray-600 mb-4">
                Your assessment history will appear here
              </p>
              <Button onClick={() => setActiveTab("individual")}>
                Start New Assessment
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
      </div>
    </div>
  );
};

export default RiskAssessment; 