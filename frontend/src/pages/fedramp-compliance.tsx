import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { apiCall } from '@/lib/utils';
import { API_ENDPOINTS } from '../config/api';
import { 
  Shield, 
  Clock, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  TrendingUp,
  FileText,
  Settings,
  Download,
  Upload
} from 'lucide-react';

interface FedRAMPAssessment {
  cve_id: string;
  risk_score: number;
  is_credibly_exploitable: boolean;
  potential_adverse_impact: string;
  priority_level: string;
  explanation: string;
  compliance_notes: string;
}

interface FedRAMPTimeline {
  remediation_deadline: string;
  days_remaining: number;
  status: string;
  escalation_required: boolean;
  responsible_team: string;
  mitigation_actions: string[];
}

interface FedRAMPComplianceReport {
  organization: string;
  report_period: string;
  compliance_metrics: {
    total_vulnerabilities: number;
    compliance_rate: number;
    overdue_count: number;
    at_risk_count: number;
    timeline_adherence: {
      '3_day_compliance': number;
      '7_day_compliance': number;
      '21_day_compliance': number;
      '180_day_compliance': number;
    };
  };
  recommendations: string[];
  audit_trail: Array<{
    timestamp: string;
    event_type: string;
    cve_id: string;
    priority_level: string;
  }>;
}

const FedRAMPCompliancePage: React.FC = () => {
  const [activeTab, setActiveTab] = useState('assessment');
  const [assessment, setAssessment] = useState<FedRAMPAssessment | null>(null);
  const [timeline, setTimeline] = useState<FedRAMPTimeline | null>(null);
  const [complianceReport, setComplianceReport] = useState<FedRAMPComplianceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Assessment form state
  const [assessmentForm, setAssessmentForm] = useState({
    cve_id: '',
    asset_criticality: 5,
    is_internet_reachable: false,
    asset_contains_federal_data: false,
    asset_mission_critical: false,
    compensating_controls: '',
    mitigation_effectiveness: 0.0
  });

  // Batch assessment state
  const [batchAssessments, setBatchAssessments] = useState<FedRAMPAssessment[]>([]);
  const [organizationName, setOrganizationName] = useState('');

  const handleAssessmentSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const data = await apiCall(API_ENDPOINTS.fedrampAssess(), {
        method: 'POST',
        body: JSON.stringify({
          ...assessmentForm,
          compensating_controls: assessmentForm.compensating_controls.split(',').map(c => c.trim()).filter(c => c)
        }),
      });

      setAssessment(data.assessment);
      setTimeline(data.timeline);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Assessment failed');
    } finally {
      setLoading(false);
    }
  };

  const handleBatchAssessment = async () => {
    if (!organizationName) {
      setError('Organization name is required');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Mock batch assessment - in real implementation, you'd have a list of vulnerabilities
      const mockAssessments = [
        {
          cve_id: 'CVE-2023-1234',
          asset_criticality: 8,
          is_internet_reachable: true,
          asset_contains_federal_data: true,
          asset_mission_critical: false,
          compensating_controls: ['WAF', 'IPS'],
          mitigation_effectiveness: 0.3
        },
        {
          cve_id: 'CVE-2023-5678',
          asset_criticality: 6,
          is_internet_reachable: false,
          asset_contains_federal_data: false,
          asset_mission_critical: true,
          compensating_controls: ['Network Segmentation'],
          mitigation_effectiveness: 0.7
        }
      ];

      const data = await apiCall(API_ENDPOINTS.fedrampBatchAssess(), {
        method: 'POST',
        body: JSON.stringify({
          assessments: mockAssessments,
          organization_name: organizationName,
          assessment_date: new Date().toISOString()
        }),
      });

      setBatchAssessments(data.assessments || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Batch assessment failed');
    } finally {
      setLoading(false);
    }
  };

  const generateComplianceReport = async () => {
    setLoading(true);
    setError(null);

    try {
      const data = await apiCall(API_ENDPOINTS.fedrampComplianceReport(organizationName || 'demo', 30));
      setComplianceReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'CRITICAL': return 'bg-red-500';
      case 'HIGH': return 'bg-orange-500';
      case 'MEDIUM': return 'bg-yellow-500';
      case 'LOW': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'on_track': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'at_risk': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'overdue': return <XCircle className="h-4 w-4 text-red-500" />;
      default: return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Demo Banner */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
        <div className="flex items-start space-x-3">
          <div className="flex-shrink-0">
            <Shield className="h-5 w-5 text-blue-600" />
          </div>
          <div className="flex-1">
            <div className="flex items-center space-x-2 mb-2">
              <h3 className="text-sm font-medium text-blue-900">FedRAMP RFC-0012 Compliance Demo</h3>
              <Badge variant="secondary" className="bg-blue-100 text-blue-800 text-xs">RFC Pending</Badge>
            </div>
            <p className="text-sm text-blue-700 mb-2">
              This feature is pending finalization of FedRAMP RFC-0012 and FedRAMP 20X announcements. 
              The demo shows the expected compliance workflow and assessment methodology.
            </p>
            <p className="text-xs text-blue-600">
              ⚠️ This is a preview of the FedRAMP compliance framework. Actual compliance features will be available in upcoming releases.
            </p>
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">FedRAMP RFC-0012 Compliance</h1>
          <p className="text-gray-600 mt-2">
            Continuous Vulnerability Monitoring Framework Implementation
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          RFC-0012 Compliant
        </Badge>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="assessment" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Assessment
          </TabsTrigger>
          <TabsTrigger value="timeline" className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Timeline
          </TabsTrigger>
          <TabsTrigger value="compliance" className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4" />
            Compliance
          </TabsTrigger>
          <TabsTrigger value="reports" className="flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Reports
          </TabsTrigger>
        </TabsList>

        <TabsContent value="assessment" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Assessment Form */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  RFC-0012 Risk Assessment
                </CardTitle>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleAssessmentSubmit} className="space-y-4">
                  <div>
                    <Label htmlFor="cve_id">CVE ID</Label>
                    <Input
                      id="cve_id"
                      value={assessmentForm.cve_id}
                      onChange={(e) => setAssessmentForm({...assessmentForm, cve_id: e.target.value})}
                      placeholder="CVE-2023-1234"
                      required
                    />
                  </div>

                  <div>
                    <Label htmlFor="asset_criticality">Asset Criticality (1-10)</Label>
                    <Input
                      id="asset_criticality"
                      type="number"
                      min="1"
                      max="10"
                      value={assessmentForm.asset_criticality}
                      onChange={(e) => setAssessmentForm({...assessmentForm, asset_criticality: parseInt(e.target.value)})}
                      required
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Asset Context</Label>
                    <div className="space-y-2">
                      <div className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          id="is_internet_reachable"
                          checked={assessmentForm.is_internet_reachable}
                          onChange={(e) => setAssessmentForm({...assessmentForm, is_internet_reachable: e.target.checked})}
                          aria-label="Internet Reachable"
                        />
                        <Label htmlFor="is_internet_reachable">Internet Reachable</Label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          id="asset_contains_federal_data"
                          checked={assessmentForm.asset_contains_federal_data}
                          onChange={(e) => setAssessmentForm({...assessmentForm, asset_contains_federal_data: e.target.checked})}
                          aria-label="Contains Federal Data"
                        />
                        <Label htmlFor="asset_contains_federal_data">Contains Federal Data</Label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          id="asset_mission_critical"
                          checked={assessmentForm.asset_mission_critical}
                          onChange={(e) => setAssessmentForm({...assessmentForm, asset_mission_critical: e.target.checked})}
                          aria-label="Mission Critical"
                        />
                        <Label htmlFor="asset_mission_critical">Mission Critical</Label>
                      </div>
                    </div>
                  </div>

                  <div>
                    <Label htmlFor="compensating_controls">Compensating Controls (comma-separated)</Label>
                    <Input
                      id="compensating_controls"
                      value={assessmentForm.compensating_controls}
                      onChange={(e) => setAssessmentForm({...assessmentForm, compensating_controls: e.target.value})}
                      placeholder="WAF, IPS, Network Segmentation"
                    />
                  </div>

                  <div>
                    <Label htmlFor="mitigation_effectiveness">Mitigation Effectiveness (0.0-1.0)</Label>
                    <Input
                      id="mitigation_effectiveness"
                      type="number"
                      min="0"
                      max="1"
                      step="0.1"
                      value={assessmentForm.mitigation_effectiveness}
                      onChange={(e) => setAssessmentForm({...assessmentForm, mitigation_effectiveness: parseFloat(e.target.value)})}
                    />
                  </div>

                  <Button type="submit" disabled={loading} className="w-full">
                    {loading ? 'Assessing...' : 'Perform Assessment'}
                  </Button>
                </form>
              </CardContent>
            </Card>

            {/* Assessment Results */}
            {assessment && (
              <Card>
                <CardHeader>
                  <CardTitle>Assessment Results</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="font-medium">CVE ID:</span>
                    <Badge variant="outline">{assessment.cve_id}</Badge>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="font-medium">Risk Score:</span>
                    <Badge className={getPriorityColor(assessment.priority_level)}>
                      {assessment.risk_score.toFixed(2)}
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="font-medium">Priority:</span>
                    <Badge className={getPriorityColor(assessment.priority_level)}>
                      {assessment.priority_level}
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="font-medium">Credibly Exploitable:</span>
                    <Badge variant={assessment.is_credibly_exploitable ? "destructive" : "secondary"}>
                      {assessment.is_credibly_exploitable ? 'Yes' : 'No'}
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="font-medium">Impact Level:</span>
                    <Badge variant="outline">{assessment.potential_adverse_impact}</Badge>
                  </div>

                  <div className="space-y-2">
                    <Label className="font-medium">Explanation:</Label>
                    <Textarea
                      value={assessment.explanation}
                      readOnly
                      className="min-h-[100px]"
                    />
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Batch Assessment */}
          <Card>
            <CardHeader>
              <CardTitle>Batch Assessment</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="organization_name">Organization Name</Label>
                <Input
                  id="organization_name"
                  value={organizationName}
                  onChange={(e) => setOrganizationName(e.target.value)}
                  placeholder="Enter organization name"
                />
              </div>
              <Button onClick={handleBatchAssessment} disabled={loading || !organizationName}>
                {loading ? 'Processing...' : 'Run Batch Assessment'}
              </Button>

              {batchAssessments.length > 0 && (
                <div className="space-y-2">
                  <Label>Batch Results:</Label>
                  <div className="space-y-2">
                    {batchAssessments.map((assessment, index) => (
                      <div key={index} className="flex items-center justify-between p-2 border rounded">
                        <span>{assessment.cve_id}</span>
                        <Badge className={getPriorityColor(assessment.priority_level)}>
                          {assessment.priority_level}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="timeline" className="space-y-6">
          {timeline && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  Remediation Timeline
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="font-medium">Status:</Label>
                    <div className="flex items-center gap-2 mt-1">
                      {getStatusIcon(timeline.status)}
                      <Badge variant="outline">{timeline.status}</Badge>
                    </div>
                  </div>

                  <div>
                    <Label className="font-medium">Days Remaining:</Label>
                    <div className="text-2xl font-bold mt-1">{timeline.days_remaining}</div>
                  </div>

                  <div>
                    <Label className="font-medium">Responsible Team:</Label>
                    <div className="mt-1">{timeline.responsible_team}</div>
                  </div>

                  <div>
                    <Label className="font-medium">Escalation Required:</Label>
                    <div className="mt-1">
                      <Badge variant={timeline.escalation_required ? "destructive" : "secondary"}>
                        {timeline.escalation_required ? 'Yes' : 'No'}
                      </Badge>
                    </div>
                  </div>
                </div>

                <div>
                  <Label className="font-medium">Mitigation Actions:</Label>
                  <ul className="list-disc list-inside mt-2 space-y-1">
                    {timeline.mitigation_actions.map((action, index) => (
                      <li key={index} className="text-sm">{action}</li>
                    ))}
                  </ul>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="compliance" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" />
                Compliance Metrics
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Button onClick={generateComplianceReport} disabled={loading}>
                {loading ? 'Generating...' : 'Generate Compliance Report'}
              </Button>

              {complianceReport && (
                <div className="mt-6 space-y-6">
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold">{complianceReport.compliance_metrics.total_vulnerabilities}</div>
                      <div className="text-sm text-gray-600">Total Vulnerabilities</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-600">
                        {complianceReport.compliance_metrics.compliance_rate}%
                      </div>
                      <div className="text-sm text-gray-600">Compliance Rate</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-red-600">
                        {complianceReport.compliance_metrics.overdue_count}
                      </div>
                      <div className="text-sm text-gray-600">Overdue</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-yellow-600">
                        {complianceReport.compliance_metrics.at_risk_count}
                      </div>
                      <div className="text-sm text-gray-600">At Risk</div>
                    </div>
                  </div>

                  <div>
                    <Label className="font-medium">Timeline Adherence:</Label>
                    <div className="space-y-2 mt-2">
                      <div className="flex items-center justify-between">
                        <span>3-Day Compliance:</span>
                        <Progress value={complianceReport.compliance_metrics.timeline_adherence['3_day_compliance']} />
                      </div>
                      <div className="flex items-center justify-between">
                        <span>7-Day Compliance:</span>
                        <Progress value={complianceReport.compliance_metrics.timeline_adherence['7_day_compliance']} />
                      </div>
                      <div className="flex items-center justify-between">
                        <span>21-Day Compliance:</span>
                        <Progress value={complianceReport.compliance_metrics.timeline_adherence['21_day_compliance']} />
                      </div>
                      <div className="flex items-center justify-between">
                        <span>180-Day Compliance:</span>
                        <Progress value={complianceReport.compliance_metrics.timeline_adherence['180_day_compliance']} />
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reports" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Compliance Reports
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Button variant="outline" className="flex items-center gap-2">
                  <Download className="h-4 w-4" />
                  Export PDF
                </Button>
                <Button variant="outline" className="flex items-center gap-2">
                  <Download className="h-4 w-4" />
                  Export CSV
                </Button>
                <Button variant="outline" className="flex items-center gap-2">
                  <Upload className="h-4 w-4" />
                  Import Data
                </Button>
              </div>

              {complianceReport && (
                <div className="space-y-4">
                  <div>
                    <Label className="font-medium">Recommendations:</Label>
                    <ul className="list-disc list-inside mt-2 space-y-1">
                      {complianceReport.recommendations.map((rec, index) => (
                        <li key={index} className="text-sm">{rec}</li>
                      ))}
                    </ul>
                  </div>

                  <div>
                    <Label className="font-medium">Audit Trail:</Label>
                    <div className="space-y-2 mt-2">
                      {complianceReport.audit_trail.map((event, index) => (
                        <div key={index} className="flex items-center justify-between p-2 border rounded text-sm">
                          <span>{event.cve_id}</span>
                          <Badge className={getPriorityColor(event.priority_level)}>
                            {event.priority_level}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  );
};

export default FedRAMPCompliancePage; 