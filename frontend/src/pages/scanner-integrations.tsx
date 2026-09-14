import { API_ENDPOINTS } from "../config/api";
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Shield,
  Zap,
  Search,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Settings,
  Download,
  Upload,
  Code,
  Server,
  Globe,
  Container,
  RefreshCw,
  Calendar,
  Save,
  Edit,
  Trash2,
  Eye,
  EyeOff,
  Filter,
  SortAsc,
  SortDesc,
  MoreHorizontal,
  Copy,
  Share,
  Bookmark,
  History,
  TrendingUp,
  BarChart3,
  FileText,
  Database,
  Network,
  Lock,
  Unlock,
  Key,
  Bell,
  BellOff,
  Timer,
  Target,
  MapPin,
  Layers,
  GitBranch,
  Cloud,
  HardDrive,
  Monitor,
  Smartphone,
  Tablet
} from "lucide-react";

interface Scanner {
  type: string;
  name: string;
  description: string;
  capabilities: string[];
  supported_formats: string[];
  requires_auth: boolean;
}

interface ScanResult {
  scan_id: string;
  scanner_type: string;
  target: string;
  status: string;
  start_time: string;
  end_time?: string;
  findings: any[];
  summary: any;
  error?: string;
}

interface ScannerStatus {
  scanner_type: string;
  available: boolean;
  version?: string;
  configured: boolean;
  error?: string;
}

interface ScanProfile {
  id: string;
  name: string;
  description: string;
  scanners: string[];
  targets: string[];
  options: Record<string, any>;
  schedule?: string;
  enabled: boolean;
  created_at: string;
  last_run?: string;
}

interface ScanHistory {
  scan_id: string;
  profile_name: string;
  scanners: string[];
  targets: string[];
  status: string;
  start_time: string;
  end_time?: string;
  findings_count: number;
  severity_breakdown: Record<string, number>;
}

const ScannerIntegrationsPage: React.FC = () => {
  const [scanners, setScanners] = useState<Scanner[]>([]);
  const [scannerStatuses, setScannerStatuses] = useState<Record<string, ScannerStatus>>({});
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [scanProfiles, setScanProfiles] = useState<ScanProfile[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanHistory[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedScanners, setSelectedScanners] = useState<string[]>([]);
  const [targets, setTargets] = useState<string>('');
  const [scanOptions, setScanOptions] = useState<Record<string, any>>({});
  const [activeTab, setActiveTab] = useState<'dashboard' | 'profiles' | 'history' | 'config'>('dashboard');
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [selectedProfile, setSelectedProfile] = useState<ScanProfile | null>(null);
  const [isEditingProfile, setIsEditingProfile] = useState(false);

  useEffect(() => {
    loadScanners();
    loadScannerStatuses();
    loadScanProfiles();
    loadScanHistory();
  }, []);

  const loadScanners = async () => {
    try {
      const response = await fetch(API_ENDPOINTS.scanners());
      if (response.ok) {
        const data = await response.json();
        setScanners(data.scanners);
      }
    } catch (err) {
      console.error('Failed to load scanners:', err);
    }
  };

  const loadScannerStatuses = async () => {
    const scannerTypes = ['nuclei', 'nessus', 'openvas', 'trivy', 'zap', 'sonarqube'];
    const statuses: Record<string, ScannerStatus> = {};

    for (const scannerType of scannerTypes) {
      try {
        const response = await fetch(API_ENDPOINTS.scannerStatus(scannerType));
        if (response.ok) {
          const status = await response.json();
          statuses[scannerType] = status;
        }
      } catch (err) {
        console.error(`Failed to load status for ${scannerType}:`, err);
        statuses[scannerType] = {
          scanner_type: scannerType,
          available: false,
          configured: false,
          error: 'Failed to check status'
        };
      }
    }

    setScannerStatuses(statuses);
  };

  const loadScanProfiles = async () => {
    // Mock data for now - would be API call in real implementation
    const profiles: ScanProfile[] = [
      {
        id: '1',
        name: 'Web Application Security',
        description: 'Comprehensive web application vulnerability scanning',
        scanners: ['nuclei', 'zap'],
        targets: ['https://example.com', 'https://testphp.vulnweb.com'],
        options: { severity: 'high', rate_limit: 150 },
        schedule: '0 2 * * *', // Daily at 2 AM
        enabled: true,
        created_at: '2024-01-15T10:00:00Z',
        last_run: '2024-01-19T02:00:00Z'
      },
      {
        id: '2',
        name: 'Container Security',
        description: 'Container and infrastructure security scanning',
        scanners: ['trivy'],
        targets: ['alpine:latest', 'nginx:latest', 'python:3.9'],
        options: { severity: 'HIGH,CRITICAL', ignore_unfixed: true },
        enabled: true,
        created_at: '2024-01-16T14:30:00Z',
        last_run: '2024-01-19T03:00:00Z'
      },
      {
        id: '3',
        name: 'Network Infrastructure',
        description: 'Network and infrastructure vulnerability assessment',
        scanners: ['nuclei', 'openvas'],
        targets: ['192.168.1.1', '10.0.0.1'],
        options: { severity: 'critical,high', templates: 'network' },
        enabled: false,
        created_at: '2024-01-17T09:15:00Z'
      }
    ];
    setScanProfiles(profiles);
  };

  const loadScanHistory = async () => {
    // Mock data for now - would be API call in real implementation
    const history: ScanHistory[] = [
      {
        scan_id: 'scan_001',
        profile_name: 'Web Application Security',
        scanners: ['nuclei', 'zap'],
        targets: ['https://example.com'],
        status: 'completed',
        start_time: '2024-01-19T02:00:00Z',
        end_time: '2024-01-19T02:15:00Z',
        findings_count: 5,
        severity_breakdown: { critical: 1, high: 2, medium: 2, low: 0 }
      },
      {
        scan_id: 'scan_002',
        profile_name: 'Container Security',
        scanners: ['trivy'],
        targets: ['alpine:latest'],
        status: 'completed',
        start_time: '2024-01-19T03:00:00Z',
        end_time: '2024-01-19T03:05:00Z',
        findings_count: 3,
        severity_breakdown: { critical: 0, high: 1, medium: 2, low: 0 }
      }
    ];
    setScanHistory(history);
  };

  const runSingleScan = async (scannerType: string, target: string) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(API_ENDPOINTS.scannerScan(), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scanner_type: scannerType,
          target: target,
          options: scanOptions[scannerType] || {}
        }),
      });

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.status}`);
      }

      const result = await response.json();
      setScanResults(prev => [result, ...prev]);
    } catch (err) {
      console.error('Scan error:', err);
      setError(err instanceof Error ? err.message : 'Failed to run scan');
    } finally {
      setIsLoading(false);
    }
  };

  const runMultiScan = async () => {
    if (!targets.trim() || selectedScanners.length === 0) {
      setError('Please select at least one scanner and provide targets');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const targetList = targets.split('\n').map(t => t.trim()).filter(t => t);
      
      const response = await fetch(API_ENDPOINTS.scannerMultiScan(), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targets: targetList,
          scanners: selectedScanners,
          options: scanOptions
        }),
      });

      if (!response.ok) {
        throw new Error(`Multi-scan failed: ${response.status}`);
      }

      const result = await response.json();
      setScanResults(prev => [...result.results, ...prev]);
    } catch (err) {
      console.error('Multi-scan error:', err);
      setError(err instanceof Error ? err.message : 'Failed to run multi-scan');
    } finally {
      setIsLoading(false);
    }
  };

  const runProfileScan = async (profile: ScanProfile) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(API_ENDPOINTS.scannerMultiScan(), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targets: profile.targets,
          scanners: profile.scanners,
          options: profile.options
        }),
      });

      if (!response.ok) {
        throw new Error(`Profile scan failed: ${response.status}`);
      }

      const result = await response.json();
      setScanResults(prev => [...result.results, ...prev]);
    } catch (err) {
      console.error('Profile scan error:', err);
      setError(err instanceof Error ? err.message : 'Failed to run profile scan');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleScanner = (scannerType: string) => {
    setSelectedScanners(prev => 
      prev.includes(scannerType) 
        ? prev.filter(s => s !== scannerType)
        : [...prev, scannerType]
    );
  };

  const getScannerIcon = (scannerType: string) => {
    switch (scannerType) {
      case 'nuclei': return <Zap className="h-5 w-5" />;
      case 'nessus': return <Shield className="h-5 w-5" />;
      case 'openvas': return <Search className="h-5 w-5" />;
      case 'trivy': return <Container className="h-5 w-5" />;
      case 'zap': return <Globe className="h-5 w-5" />;
      case 'sonarqube': return <Code className="h-5 w-5" />;
      default: return <Server className="h-5 w-5" />;
    }
  };

  const getStatusIcon = (status: ScannerStatus) => {
    if (status.available && status.configured) {
      return <CheckCircle className="h-4 w-4 text-green-500" />;
    } else if (status.available) {
      return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    } else {
      return <XCircle className="h-4 w-4 text-red-500" />;
    }
  };

  const getStatusColor = (status: ScannerStatus) => {
    if (status.available && status.configured) return 'bg-green-100 text-green-800';
    if (status.available) return 'bg-yellow-100 text-yellow-800';
    return 'bg-red-100 text-red-800';
  };

  const getTargetIcon = (target: string) => {
    if (target.includes('http')) return <Globe className="h-4 w-4" />;
    if (target.includes(':')) return <Container className="h-4 w-4" />;
    if (target.match(/^\d+\.\d+\.\d+\.\d+$/)) return <Network className="h-4 w-4" />;
    return <Target className="h-4 w-4" />;
  };

  return (
    <main className="flex flex-col items-center py-8">
      {/* Demo Banner */}
      <div className="w-full max-w-7xl mb-6">
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
          <div className="flex items-start space-x-3">
            <div className="flex-shrink-0">
              <Search className="h-5 w-5 text-green-600" />
            </div>
            <div className="flex-1">
              <div className="flex items-center space-x-2 mb-2">
                <h3 className="text-sm font-medium text-green-900">Scanner Integration Demo</h3>
                <Badge variant="secondary" className="bg-green-100 text-green-800 text-xs">Scanner Demo</Badge>
              </div>
              <p className="text-sm text-green-700 mb-2">
                Preview our multi-scanner integration capabilities. 
                See how VulnRisk will connect with popular security scanners for comprehensive assessment.
              </p>
              <p className="text-xs text-green-600">
                🔍 This is a demonstration of scanner integration features. Real scanner connections will be available in upcoming releases.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="text-center mb-8">
        <h1 className="text-4xl font-bold mb-4 flex items-center justify-center">
          <Shield className="mr-3 h-8 w-8 text-blue-600" />
          Advanced Scanner Integrations
        </h1>
        <p className="text-lg text-gray-700">Enterprise-grade vulnerability scanning with advanced features</p>
      </div>

      {/* Navigation Tabs */}
      <div className="w-full max-w-7xl mb-6">
        <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'dashboard' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <BarChart3 className="inline mr-2 h-4 w-4" />
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab('profiles')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'profiles' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <Bookmark className="inline mr-2 h-4 w-4" />
            Scan Profiles
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'history' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <History className="inline mr-2 h-4 w-4" />
            Scan History
          </button>
          <button
            onClick={() => setActiveTab('config')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'config' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <Settings className="inline mr-2 h-4 w-4" />
            Configuration
          </button>
        </div>
      </div>

      <div className="w-full max-w-7xl space-y-8">
        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <>
            {/* Scanner Status Overview */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Settings className="mr-2 h-5 w-5" />
                  Scanner Status Overview
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {scanners.map((scanner) => {
                    const status = scannerStatuses[scanner.type];
                    return (
                      <div key={scanner.type} className="border rounded-lg p-4 hover:shadow-md transition-shadow">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center">
                            {getScannerIcon(scanner.type)}
                            <span className="ml-2 font-semibold">{scanner.name}</span>
                          </div>
                          {status && getStatusIcon(status)}
                        </div>
                        <p className="text-sm text-gray-600 mb-2">{scanner.description}</p>
                        <div className="flex flex-wrap gap-1 mb-2">
                          {scanner.capabilities.map((cap) => (
                            <Badge key={cap} variant="outline" className="text-xs">
                              {cap}
                            </Badge>
                          ))}
                        </div>
                        {status && (
                          <div className={`text-xs px-2 py-1 rounded ${getStatusColor(status)}`}>
                            {status.available && status.configured ? 'Ready' : 
                             status.available ? 'Available (needs config)' : 'Not available'}
                            {status.version && ` - ${status.version}`}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Play className="mr-2 h-5 w-5" />
                  Quick Actions
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {/* Multi-Scanner Configuration */}
                  <div className="space-y-4">
                    <h3 className="font-semibold text-lg">Multi-Scanner Scan</h3>
                    <div>
                      <label className="block text-sm font-medium mb-2">Select Scanners</label>
                      <div className="grid grid-cols-2 gap-2">
                        {scanners.map((scanner) => {
                          const status = scannerStatuses[scanner.type];
                          const isSelected = selectedScanners.includes(scanner.type);
                          const isAvailable = status?.available && status?.configured;
                          
                          return (
                            <Button
                              key={scanner.type}
                              variant={isSelected ? "default" : "outline"}
                              onClick={() => toggleScanner(scanner.type)}
                              disabled={!isAvailable}
                              className="justify-start"
                              size="sm"
                            >
                              {getScannerIcon(scanner.type)}
                              <span className="ml-2">{scanner.name}</span>
                            </Button>
                          );
                        })}
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium mb-2">
                        Targets (one per line)
                      </label>
                      <textarea
                        value={targets}
                        onChange={(e) => setTargets(e.target.value)}
                        placeholder="https://example.com&#10;192.168.1.1&#10;docker.io/library/nginx:latest"
                        className="w-full h-24 p-3 border rounded-md"
                      />
                    </div>

                    <Button
                      onClick={runMultiScan}
                      disabled={isLoading || selectedScanners.length === 0 || !targets.trim()}
                      className="w-full"
                    >
                      <Play className="mr-2 h-4 w-4" />
                      {isLoading ? 'Running Scans...' : 'Run Multi-Scanner Scan'}
                    </Button>
                  </div>

                  {/* Quick Single Scans */}
                  <div className="space-y-4">
                    <h3 className="font-semibold text-lg">Quick Single Scans</h3>
                    <div className="grid grid-cols-1 gap-3">
                      {scanners.map((scanner) => {
                        const status = scannerStatuses[scanner.type];
                        const isAvailable = status?.available && status?.configured;
                        
                        return (
                          <div key={scanner.type} className="border rounded-lg p-3">
                            <div className="flex items-center mb-2">
                              {getScannerIcon(scanner.type)}
                              <span className="ml-2 font-semibold text-sm">{scanner.name}</span>
                            </div>
                            <input
                              type="text"
                              placeholder="Enter target..."
                              className="w-full p-2 border rounded-md mb-2 text-sm"
                              onKeyPress={(e) => {
                                if (e.key === 'Enter') {
                                  const target = e.currentTarget.value.trim();
                                  if (target && isAvailable) {
                                    runSingleScan(scanner.type, target);
                                  }
                                }
                              }}
                            />
                            <Button
                              onClick={() => {
                                const target = document.querySelector(`input[placeholder="Enter target..."]`) as HTMLInputElement;
                                if (target?.value.trim() && isAvailable) {
                                  runSingleScan(scanner.type, target.value.trim());
                                }
                              }}
                              disabled={!isAvailable || isLoading}
                              size="sm"
                              className="w-full"
                            >
                              {isLoading ? 'Scanning...' : 'Scan'}
                            </Button>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Recent Profiles */}
                  <div className="space-y-4">
                    <h3 className="font-semibold text-lg">Recent Profiles</h3>
                    <div className="space-y-3">
                      {scanProfiles.slice(0, 3).map((profile) => (
                        <div key={profile.id} className="border rounded-lg p-3">
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="font-medium text-sm">{profile.name}</h4>
                            <Badge variant={profile.enabled ? "default" : "secondary"} className="text-xs">
                              {profile.enabled ? 'Active' : 'Inactive'}
                            </Badge>
                          </div>
                          <p className="text-xs text-gray-600 mb-2">{profile.description}</p>
                          <div className="flex items-center gap-2 mb-2">
                            {profile.scanners.map(scanner => getScannerIcon(scanner))}
                            <span className="text-xs text-gray-500">{profile.scanners.length} scanners</span>
                          </div>
                          <Button
                            onClick={() => runProfileScan(profile)}
                            disabled={isLoading}
                            size="sm"
                            className="w-full"
                          >
                            <Play className="mr-2 h-3 w-3" />
                            Run Profile
                          </Button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </>
        )}

        {/* Scan Profiles Tab */}
        {activeTab === 'profiles' && (
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center">
                  <Bookmark className="mr-2 h-5 w-5" />
                  Scan Profiles
                </CardTitle>
                <Button onClick={() => setIsEditingProfile(true)}>
                  <Save className="mr-2 h-4 w-4" />
                  Create Profile
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {scanProfiles.map((profile) => (
                  <div key={profile.id} className="border rounded-lg p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-semibold">{profile.name}</h3>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedProfile(profile)}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => runProfileScan(profile)}
                          disabled={isLoading}
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setSelectedProfile(profile);
                            setIsEditingProfile(true);
                          }}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    
                    <p className="text-sm text-gray-600 mb-3">{profile.description}</p>
                    
                    <div className="space-y-2 mb-3">
                      <div className="flex items-center gap-2">
                        <Layers className="h-4 w-4 text-gray-500" />
                        <span className="text-sm font-medium">Scanners:</span>
                        <div className="flex gap-1">
                          {profile.scanners.map(scanner => (
                            <Badge key={scanner} variant="outline" className="text-xs">
                              {scanner}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        <Target className="h-4 w-4 text-gray-500" />
                        <span className="text-sm font-medium">Targets:</span>
                        <span className="text-sm text-gray-600">{profile.targets.length}</span>
                      </div>
                      
                      {profile.schedule && (
                        <div className="flex items-center gap-2">
                          <Calendar className="h-4 w-4 text-gray-500" />
                          <span className="text-sm font-medium">Schedule:</span>
                          <span className="text-sm text-gray-600">{profile.schedule}</span>
                        </div>
                      )}
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <Badge variant={profile.enabled ? "default" : "secondary"}>
                        {profile.enabled ? 'Active' : 'Inactive'}
                      </Badge>
                      {profile.last_run && (
                        <span className="text-xs text-gray-500">
                          Last run: {new Date(profile.last_run).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Scan History Tab */}
        {activeTab === 'history' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <History className="mr-2 h-5 w-5" />
                Scan History
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {scanHistory.map((scan) => (
                  <div key={scan.scan_id} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <h3 className="font-semibold">{scan.profile_name}</h3>
                        <Badge 
                          variant={scan.status === 'completed' ? 'default' : 'destructive'}
                        >
                          {scan.status}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button variant="ghost" size="sm">
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm">
                          <Download className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm">
                          <Share className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-3">
                      <div className="flex items-center gap-2">
                        <Layers className="h-4 w-4 text-gray-500" />
                        <span className="text-sm">
                          <span className="font-medium">Scanners:</span> {scan.scanners.join(', ')}
                        </span>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        <Target className="h-4 w-4 text-gray-500" />
                        <span className="text-sm">
                          <span className="font-medium">Targets:</span> {scan.targets.length}
                        </span>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-gray-500" />
                        <span className="text-sm">
                          <span className="font-medium">Findings:</span> {scan.findings_count}
                        </span>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-4 mb-3">
                      <span className="text-sm text-gray-600">
                        Started: {new Date(scan.start_time).toLocaleString()}
                      </span>
                      {scan.end_time && (
                        <span className="text-sm text-gray-600">
                          Duration: {Math.round((new Date(scan.end_time).getTime() - new Date(scan.start_time).getTime()) / 1000)}s
                        </span>
                      )}
                    </div>
                    
                    <div className="flex gap-2">
                      {Object.entries(scan.severity_breakdown).map(([severity, count]) => (
                        <Badge key={severity} variant="outline" className="text-xs">
                          {severity}: {count}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Configuration Tab */}
        {activeTab === 'config' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Settings className="mr-2 h-5 w-5" />
                Scanner Configuration
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* Scanner Settings */}
                <div className="space-y-6">
                  <h3 className="text-lg font-semibold">Scanner Settings</h3>
                  
                  {scanners.map((scanner) => {
                    const status = scannerStatuses[scanner.type];
                    return (
                      <div key={scanner.type} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center">
                            {getScannerIcon(scanner.type)}
                            <span className="ml-2 font-semibold">{scanner.name}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {status && getStatusIcon(status)}
                            <Button variant="ghost" size="sm">
                              <Settings className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                        
                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-sm">
                            <span>Status:</span>
                            <Badge variant={status?.available && status?.configured ? "default" : "secondary"}>
                              {status?.available && status?.configured ? 'Configured' : 'Not Configured'}
                            </Badge>
                          </div>
                          
                          {status?.version && (
                            <div className="flex items-center justify-between text-sm">
                              <span>Version:</span>
                              <span className="text-gray-600">{status.version}</span>
                            </div>
                          )}
                          
                          <div className="flex items-center justify-between text-sm">
                            <span>Authentication:</span>
                            <Badge variant={scanner.requires_auth ? "destructive" : "default"}>
                              {scanner.requires_auth ? 'Required' : 'Not Required'}
                            </Badge>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Global Settings */}
                <div className="space-y-6">
                  <h3 className="text-lg font-semibold">Global Settings</h3>
                  
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium mb-2">Default Scan Timeout</label>
                      <select className="w-full p-2 border rounded-md" aria-label="Select scan timeout">
                        <option value="300">5 minutes</option>
                        <option value="600">10 minutes</option>
                        <option value="1800">30 minutes</option>
                        <option value="3600">1 hour</option>
                      </select>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium mb-2">Default Severity Level</label>
                      <select className="w-full p-2 border rounded-md" aria-label="Select default severity level">
                        <option value="all">All Severities</option>
                        <option value="critical,high">Critical & High</option>
                        <option value="critical">Critical Only</option>
                        <option value="high">High & Above</option>
                      </select>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium mb-2">Notification Settings</label>
                      <div className="space-y-2">
                        <label className="flex items-center">
                          <input type="checkbox" className="mr-2" defaultChecked />
                          Email notifications for completed scans
                        </label>
                        <label className="flex items-center">
                          <input type="checkbox" className="mr-2" />
                          Slack notifications for critical findings
                        </label>
                        <label className="flex items-center">
                          <input type="checkbox" className="mr-2" defaultChecked />
                          Dashboard alerts for failed scans
                        </label>
                      </div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium mb-2">Data Retention</label>
                      <select className="w-full p-2 border rounded-md" aria-label="Select data retention period">
                        <option value="30">30 days</option>
                        <option value="90">90 days</option>
                        <option value="365">1 year</option>
                        <option value="0">Keep forever</option>
                      </select>
                    </div>
                  </div>
                  
                  <div className="flex gap-2">
                    <Button>
                      <Save className="mr-2 h-4 w-4" />
                      Save Settings
                    </Button>
                    <Button variant="outline">
                      <RefreshCw className="mr-2 h-4 w-4" />
                      Reset to Defaults
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Error Display */}
        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Scan Results */}
        {scanResults.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Download className="mr-2 h-5 w-5" />
                Recent Scan Results
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {scanResults.slice(0, 5).map((result, index) => (
                  <div key={index} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center">
                        {getScannerIcon(result.scanner_type)}
                        <span className="ml-2 font-semibold">{result.scanner_type.toUpperCase()}</span>
                        <Badge 
                          variant={result.status === 'completed' ? 'default' : 'destructive'}
                          className="ml-2"
                        >
                          {result.status}
                        </Badge>
                      </div>
                      <span className="text-sm text-gray-500">
                        {new Date(result.start_time).toLocaleString()}
                      </span>
                    </div>
                    
                    <p className="text-sm text-gray-600 mb-2">Target: {result.target}</p>
                    
                    {result.summary && (
                      <div className="mb-2">
                        <p className="text-sm font-medium">Summary:</p>
                        <div className="flex gap-2 mt-1">
                          <Badge variant="outline">
                            Total: {result.summary.total_findings || 0}
                          </Badge>
                          {result.summary.severity_breakdown && Object.entries(result.summary.severity_breakdown).map(([severity, count]) => (
                            <Badge key={severity} variant="outline">
                              {severity}: {count}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {result.findings && result.findings.length > 0 && (
                      <div>
                        <p className="text-sm font-medium mb-2">Findings:</p>
                        <div className="max-h-40 overflow-y-auto">
                          {result.findings.slice(0, 5).map((finding, idx) => (
                            <div key={idx} className="text-sm p-2 bg-gray-50 rounded mb-1">
                              <div className="flex items-center justify-between">
                                <span className="font-medium">{finding.title || finding.cve_id}</span>
                                <Badge 
                                  variant={finding.severity === 'critical' ? 'destructive' : 'outline'}
                                  className="text-xs"
                                >
                                  {finding.severity}
                                </Badge>
                              </div>
                              {finding.description && (
                                <p className="text-xs text-gray-600 mt-1">{finding.description}</p>
                              )}
                            </div>
                          ))}
                          {result.findings.length > 5 && (
                            <p className="text-xs text-gray-500">... and {result.findings.length - 5} more findings</p>
                          )}
                        </div>
                      </div>
                    )}
                    
                    {result.error && (
                      <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>{result.error}</AlertDescription>
                      </Alert>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </main>
  );
};

export default ScannerIntegrationsPage; 