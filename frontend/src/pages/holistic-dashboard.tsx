import React, { useState, useEffect } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Progress } from '../components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { Alert, AlertDescription } from '../components/ui/alert';
import { RiskCalculator } from '../components/RiskCalculator';
import { 
  Shield, 
  Activity, 
  TrendingUp, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Clock,
  Database,
  Cpu,
  HardDrive,
  Network,
  Server,
  Users,
  FileText,
  BarChart3,
  Settings,
  RefreshCw,
  Target
} from 'lucide-react';

interface SecurityStatus {
  threat_detection: {
    status: string;
    threats_detected: number;
    blocked_ips: number;
    last_scan: string;
  };
  audit_events: {
    total_events: number;
    critical_events: number;
    recent_events: Array<{
      id: string;
      timestamp: string;
      event_type: string;
      severity: string;
      description: string;
    }>;
  };
  input_validation: {
    total_requests: number;
    blocked_requests: number;
    validation_score: number;
  };
}

interface ComplianceStatus {
  soc2: {
    status: string;
    compliance_score: number;
    controls_assessed: number;
    total_controls: number;
    last_assessment: string;
  };
  iso27001: {
    status: string;
    compliance_score: number;
    controls_assessed: number;
    total_controls: number;
    last_assessment: string;
  };
  hipaa: {
    status: string;
    compliance_score: number;
    controls_assessed: number;
    total_controls: number;
    last_assessment: string;
  };
  overall_compliance: {
    status: string;
    score: number;
    recommendations: string[];
  };
}

interface PerformanceMetrics {
  system: {
    cpu_usage: number;
    memory_usage: number;
    disk_usage: number;
    network_throughput: number;
  };
  application: {
    response_time: number;
    requests_per_second: number;
    error_rate: number;
    active_connections: number;
  };
  cache: {
    hit_rate: number;
    total_requests: number;
    cache_size: number;
    evictions: number;
  };
  database: {
    query_time: number;
    connections: number;
    slow_queries: number;
    optimization_score: number;
  };
}

interface ScalabilityStatus {
  auto_scaling: {
    status: string;
    current_instances: number;
    min_instances: number;
    max_instances: number;
    scaling_history: Array<{
      timestamp: string;
      action: string;
      reason: string;
      instances: number;
    }>;
  };
  load_balancer: {
    status: string;
    active_instances: number;
    health_checks: {
      total: number;
      healthy: number;
      unhealthy: number;
    };
    traffic_distribution: {
      strategy: string;
      requests_distributed: number;
    };
  };
  performance_alerts: Array<{
    id: string;
    type: string;
    severity: string;
    message: string;
    timestamp: string;
    resolved: boolean;
  }>;
}

const HolisticDashboard: React.FC = () => {
  const { getAccessTokenSilently, isAuthenticated, loginWithRedirect } = useAuth0();
  const [securityStatus, setSecurityStatus] = useState<SecurityStatus | null>(null);
  const [complianceStatus, setComplianceStatus] = useState<ComplianceStatus | null>(null);
  const [performanceMetrics, setPerformanceMetrics] = useState<PerformanceMetrics | null>(null);
  const [scalabilityStatus, setScalabilityStatus] = useState<ScalabilityStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  useEffect(() => {
    if (!isAuthenticated) {
      loginWithRedirect();
      return;
    }
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, [isAuthenticated]);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const token = await getAccessTokenSilently();
      
      // Fetch all dashboard data in parallel
      const [securityRes, complianceRes, performanceRes, scalabilityRes] = await Promise.all([
        fetch('/api/v1/security/threat-detection/status', {
          headers: { Authorization: `Bearer ${token}` }
        }),
        fetch('/api/v1/security/compliance/summary', {
          headers: { Authorization: `Bearer ${token}` }
        }),
        fetch('/api/v1/performance/monitoring/metrics', {
          headers: { Authorization: `Bearer ${token}` }
        }),
        fetch('/api/v1/performance/scaling/status', {
          headers: { Authorization: `Bearer ${token}` }
        })
      ]);

      if (securityRes.ok) {
        const securityData = await securityRes.json();
        setSecurityStatus(securityData);
      } else {
        console.error('Security status fetch failed:', securityRes.status);
      }

      if (complianceRes.ok) {
        const complianceData = await complianceRes.json();
        setComplianceStatus(complianceData);
      } else {
        console.error('Compliance summary fetch failed:', complianceRes.status);
      }

      if (performanceRes.ok) {
        const performanceData = await performanceRes.json();
        setPerformanceMetrics(performanceData);
      } else {
        console.error('Performance metrics fetch failed:', performanceRes.status);
      }

      if (scalabilityRes.ok) {
        const scalabilityData = await scalabilityRes.json();
        setScalabilityStatus(scalabilityData);
      } else {
        console.error('Scaling status fetch failed:', scalabilityRes.status);
      }

      setLastRefresh(new Date());
      setError(null);
    } catch (err) {
      setError('Failed to fetch dashboard data');
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'healthy':
      case 'compliant':
      case 'active':
        return 'bg-green-100 text-green-800';
      case 'warning':
      case 'partially_compliant':
        return 'bg-yellow-100 text-yellow-800';
      case 'critical':
      case 'non_compliant':
      case 'inactive':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getSeverityIcon = (severity: string | undefined) => {
    if (!severity) {
      return <Clock className="w-4 h-4 text-gray-500" />;
    }
    
    switch (severity.toLowerCase()) {
      case 'critical':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case 'info':
        return <CheckCircle className="w-4 h-4 text-blue-500" />;
      default:
        return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <Shield className="w-16 h-16 mx-auto text-gray-400 mb-4" />
          <h2 className="text-2xl font-bold mb-2">Authentication Required</h2>
          <p className="text-gray-600 mb-4">Please log in to access the holistic dashboard</p>
          <Button onClick={() => loginWithRedirect()}>Log In</Button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 mx-auto animate-spin text-blue-500 mb-4" />
          <h2 className="text-xl font-semibold">Loading Dashboard...</h2>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Holistic Dashboard</h1>
          <p className="text-gray-600">Comprehensive view of security, compliance, performance, and scalability</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="text-sm text-gray-500">
            Last updated: {lastRefresh.toLocaleTimeString()}
          </div>
          <Button onClick={fetchDashboardData} variant="outline" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Main Dashboard Tabs */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="risk">Risk Assessment</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* Security Overview */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Security Status</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {securityStatus?.threat_detection.status === 'active' ? 'Secure' : 'At Risk'}
                </div>
                <p className="text-xs text-muted-foreground">
                  {securityStatus?.threat_detection.threats_detected || 0} threats blocked
                </p>
                <Badge className={`mt-2 ${getStatusColor(securityStatus?.threat_detection.status || 'unknown')}`}>
                  {securityStatus?.threat_detection.status || 'Unknown'}
                </Badge>
              </CardContent>
            </Card>

            {/* Compliance Overview */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Compliance Score</CardTitle>
                <FileText className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {complianceStatus?.overall_compliance.score || 0}%
                </div>
                <p className="text-xs text-muted-foreground">
                  Overall compliance status
                </p>
                <Badge className={`mt-2 ${getStatusColor(complianceStatus?.overall_compliance.status || 'unknown')}`}>
                  {complianceStatus?.overall_compliance.status || 'Unknown'}
                </Badge>
              </CardContent>
            </Card>

            {/* Performance Overview */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Response Time</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {performanceMetrics?.application.response_time || 0}ms
                </div>
                <p className="text-xs text-muted-foreground">
                  Average response time
                </p>
                <Progress 
                  value={Math.min((performanceMetrics?.application.response_time || 0) / 1000 * 100, 100)} 
                  className="mt-2" 
                />
              </CardContent>
            </Card>

            {/* Scalability Overview */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Active Instances</CardTitle>
                <Server className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {scalabilityStatus?.auto_scaling.current_instances || 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  Auto-scaling active
                </p>
                <Badge className={`mt-2 ${getStatusColor(scalabilityStatus?.auto_scaling.status || 'unknown')}`}>
                  {scalabilityStatus?.auto_scaling.status || 'Unknown'}
                </Badge>
              </CardContent>
            </Card>
          </div>

          {/* Recent Alerts */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2" />
                Recent Alerts
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {scalabilityStatus?.performance_alerts?.length > 0 ? (
                  scalabilityStatus.performance_alerts.slice(0, 5).map((alert) => (
                    <div key={alert.id} className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center space-x-3">
                        {getSeverityIcon(alert.severity)}
                        <div>
                          <p className="font-medium">{alert.type}</p>
                          <p className="text-sm text-gray-600">{alert.message}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-500">{new Date(alert.timestamp).toLocaleString()}</p>
                        <Badge className={alert.resolved ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>
                          {alert.resolved ? 'Resolved' : 'Active'}
                        </Badge>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-gray-500 text-center py-4">No recent alerts</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Threat Detection */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Shield className="w-5 h-5 mr-2" />
                  Threat Detection
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-600">
                      {securityStatus?.threat_detection.threats_detected || 0}
                    </div>
                    <p className="text-sm text-gray-600">Threats Detected</p>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-600">
                      {securityStatus?.threat_detection.blocked_ips || 0}
                    </div>
                    <p className="text-sm text-gray-600">Blocked IPs</p>
                  </div>
                </div>
                <Badge className={`w-full justify-center ${getStatusColor(securityStatus?.threat_detection.status || 'unknown')}`}>
                  Status: {securityStatus?.threat_detection.status || 'Unknown'}
                </Badge>
                <p className="text-sm text-gray-500">
                  Last scan: {securityStatus?.threat_detection.last_scan ? new Date(securityStatus.threat_detection.last_scan).toLocaleString() : 'Never'}
                </p>
              </CardContent>
            </Card>

            {/* Input Validation */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Settings className="w-5 h-5 mr-2" />
                  Input Validation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm">Validation Score</span>
                    <span className="text-sm font-medium">{securityStatus?.input_validation.validation_score || 0}%</span>
                  </div>
                  <Progress value={securityStatus?.input_validation.validation_score || 0} />
                </div>
                <div className="grid grid-cols-2 gap-4 text-center">
                  <div>
                    <div className="text-lg font-bold">{securityStatus?.input_validation.total_requests || 0}</div>
                    <p className="text-sm text-gray-600">Total Requests</p>
                  </div>
                  <div>
                    <div className="text-lg font-bold text-red-600">{securityStatus?.input_validation.blocked_requests || 0}</div>
                    <p className="text-sm text-gray-600">Blocked</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Recent Audit Events */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <BarChart3 className="w-5 h-5 mr-2" />
                Recent Audit Events
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {securityStatus?.audit_events?.recent_events?.length > 0 ? (
                  securityStatus.audit_events.recent_events.slice(0, 10).map((event) => (
                    <div key={event.id || `event-${event.timestamp}`} className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center space-x-3">
                        {getSeverityIcon(event.severity)}
                        <div>
                          <p className="font-medium">{event.event_type || 'Unknown Event'}</p>
                          <p className="text-sm text-gray-600">{event.description || 'No description available'}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-500">
                          {event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown time'}
                        </p>
                        <Badge className={getStatusColor(event.severity || 'unknown')}>
                          {event.severity || 'Unknown'}
                        </Badge>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-gray-500 text-center py-4">No recent audit events</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Compliance Tab */}
        <TabsContent value="compliance" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* SOC 2 */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <FileText className="w-5 h-5 mr-2" />
                  SOC 2 Type II
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm">Compliance Score</span>
                    <span className="text-sm font-medium">{complianceStatus?.soc2.compliance_score || 0}%</span>
                  </div>
                  <Progress value={complianceStatus?.soc2.compliance_score || 0} />
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold">{complianceStatus?.soc2.controls_assessed || 0}/{complianceStatus?.soc2.total_controls || 0}</div>
                  <p className="text-sm text-gray-600">Controls Assessed</p>
                </div>
                <Badge className={`w-full justify-center ${getStatusColor(complianceStatus?.soc2.status || 'unknown')}`}>
                  {complianceStatus?.soc2.status || 'Unknown'}
                </Badge>
                <p className="text-sm text-gray-500">
                  Last assessment: {complianceStatus?.soc2.last_assessment ? new Date(complianceStatus.soc2.last_assessment).toLocaleDateString() : 'Never'}
                </p>
              </CardContent>
            </Card>

            {/* ISO 27001 */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <FileText className="w-5 h-5 mr-2" />
                  ISO 27001
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm">Compliance Score</span>
                    <span className="text-sm font-medium">{complianceStatus?.iso27001.compliance_score || 0}%</span>
                  </div>
                  <Progress value={complianceStatus?.iso27001.compliance_score || 0} />
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold">{complianceStatus?.iso27001.controls_assessed || 0}/{complianceStatus?.iso27001.total_controls || 0}</div>
                  <p className="text-sm text-gray-600">Controls Assessed</p>
                </div>
                <Badge className={`w-full justify-center ${getStatusColor(complianceStatus?.iso27001.status || 'unknown')}`}>
                  {complianceStatus?.iso27001.status || 'Unknown'}
                </Badge>
                <p className="text-sm text-gray-500">
                  Last assessment: {complianceStatus?.iso27001.last_assessment ? new Date(complianceStatus.iso27001.last_assessment).toLocaleDateString() : 'Never'}
                </p>
              </CardContent>
            </Card>

            {/* HIPAA */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <FileText className="w-5 h-5 mr-2" />
                  HIPAA
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm">Compliance Score</span>
                    <span className="text-sm font-medium">{complianceStatus?.hipaa.compliance_score || 0}%</span>
                  </div>
                  <Progress value={complianceStatus?.hipaa.compliance_score || 0} />
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold">{complianceStatus?.hipaa.controls_assessed || 0}/{complianceStatus?.hipaa.total_controls || 0}</div>
                  <p className="text-sm text-gray-600">Controls Assessed</p>
                </div>
                <Badge className={`w-full justify-center ${getStatusColor(complianceStatus?.hipaa.status || 'unknown')}`}>
                  {complianceStatus?.hipaa.status || 'Unknown'}
                </Badge>
                <p className="text-sm text-gray-500">
                  Last assessment: {complianceStatus?.hipaa.last_assessment ? new Date(complianceStatus.hipaa.last_assessment).toLocaleDateString() : 'Never'}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Compliance Recommendations */}
          {complianceStatus?.overall_compliance.recommendations && complianceStatus.overall_compliance.recommendations.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Compliance Recommendations</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {complianceStatus.overall_compliance.recommendations.map((recommendation, index) => (
                    <div key={index} className="flex items-start space-x-2 p-3 border rounded-lg">
                      <AlertTriangle className="w-4 h-4 text-yellow-500 mt-0.5" />
                      <p className="text-sm">{recommendation}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Performance Tab */}
        <TabsContent value="performance" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* System Resources */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Server className="w-5 h-5 mr-2" />
                  System Resources
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-sm flex items-center">
                        <Cpu className="w-4 h-4 mr-1" />
                        CPU Usage
                      </span>
                      <span className="text-sm font-medium">{performanceMetrics?.system.cpu_usage || 0}%</span>
                    </div>
                    <Progress value={performanceMetrics?.system.cpu_usage || 0} />
                  </div>
                  <div>
                                         <div className="flex justify-between mb-1">
                       <span className="text-sm flex items-center">
                         <HardDrive className="w-4 h-4 mr-1" />
                         Memory Usage
                       </span>
                       <span className="text-sm font-medium">{performanceMetrics?.system.memory_usage || 0}%</span>
                     </div>
                    <Progress value={performanceMetrics?.system.memory_usage || 0} />
                  </div>
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-sm flex items-center">
                        <Database className="w-4 h-4 mr-1" />
                        Disk Usage
                      </span>
                      <span className="text-sm font-medium">{performanceMetrics?.system.disk_usage || 0}%</span>
                    </div>
                    <Progress value={performanceMetrics?.system.disk_usage || 0} />
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Application Performance */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Activity className="w-5 h-5 mr-2" />
                  Application Performance
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold">{performanceMetrics?.application.response_time || 0}ms</div>
                    <p className="text-sm text-gray-600">Response Time</p>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold">{performanceMetrics?.application.requests_per_second || 0}</div>
                    <p className="text-sm text-gray-600">Requests/sec</p>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold">{performanceMetrics?.application.error_rate || 0}%</div>
                    <p className="text-sm text-gray-600">Error Rate</p>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold">{performanceMetrics?.application.active_connections || 0}</div>
                    <p className="text-sm text-gray-600">Active Connections</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Cache Performance */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Database className="w-5 h-5 mr-2" />
                  Cache Performance
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm">Cache Hit Rate</span>
                    <span className="text-sm font-medium">{performanceMetrics?.cache.hit_rate || 0}%</span>
                  </div>
                  <Progress value={performanceMetrics?.cache.hit_rate || 0} />
                </div>
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-lg font-bold">{performanceMetrics?.cache.total_requests || 0}</div>
                    <p className="text-sm text-gray-600">Total Requests</p>
                  </div>
                  <div>
                    <div className="text-lg font-bold">{performanceMetrics?.cache.cache_size || 0}</div>
                    <p className="text-sm text-gray-600">Cache Size</p>
                  </div>
                  <div>
                    <div className="text-lg font-bold">{performanceMetrics?.cache.evictions || 0}</div>
                    <p className="text-sm text-gray-600">Evictions</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Database Performance */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Database className="w-5 h-5 mr-2" />
                  Database Performance
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm">Optimization Score</span>
                    <span className="text-sm font-medium">{performanceMetrics?.database.optimization_score || 0}%</span>
                  </div>
                  <Progress value={performanceMetrics?.database.optimization_score || 0} />
                </div>
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-lg font-bold">{performanceMetrics?.database.query_time || 0}ms</div>
                    <p className="text-sm text-gray-600">Avg Query Time</p>
                  </div>
                  <div>
                    <div className="text-lg font-bold">{performanceMetrics?.database.connections || 0}</div>
                    <p className="text-sm text-gray-600">Connections</p>
                  </div>
                  <div>
                    <div className="text-lg font-bold">{performanceMetrics?.database.slow_queries || 0}</div>
                    <p className="text-sm text-gray-600">Slow Queries</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Auto-scaling Status */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <TrendingUp className="w-5 h-5 mr-2" />
                Auto-scaling Status
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium">Current Instances</span>
                    <span className="text-lg font-bold">{scalabilityStatus?.auto_scaling.current_instances || 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium">Min Instances</span>
                    <span className="text-sm">{scalabilityStatus?.auto_scaling.min_instances || 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium">Max Instances</span>
                    <span className="text-sm">{scalabilityStatus?.auto_scaling.max_instances || 0}</span>
                  </div>
                  <Badge className={`w-full justify-center ${getStatusColor(scalabilityStatus?.auto_scaling.status || 'unknown')}`}>
                    {scalabilityStatus?.auto_scaling.status || 'Unknown'}
                  </Badge>
                </div>
                <div className="space-y-4">
                  <h4 className="font-medium">Recent Scaling Events</h4>
                  <div className="space-y-2 max-h-32 overflow-y-auto">
                    {scalabilityStatus?.auto_scaling.scaling_history.slice(0, 5).map((event, index) => (
                      <div key={index} className="flex justify-between items-center text-sm">
                        <span>{event.action}</span>
                        <span className="text-gray-500">{new Date(event.timestamp).toLocaleTimeString()}</span>
                      </div>
                    ))}
                    {(!scalabilityStatus?.auto_scaling.scaling_history || scalabilityStatus.auto_scaling.scaling_history.length === 0) && (
                      <p className="text-gray-500 text-sm">No recent scaling events</p>
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Risk Assessment Tab */}
        <TabsContent value="risk" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Target className="w-5 h-5 mr-2" />
                Risk Assessment
              </CardTitle>
            </CardHeader>
            <CardContent>
              <RiskCalculator />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default HolisticDashboard; 