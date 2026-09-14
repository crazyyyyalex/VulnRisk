import { API_ENDPOINTS } from "../config/api";
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { 
  Brain, 
  TrendingUp, 
  AlertTriangle, 
  Lightbulb, 
  Target,
  Activity,
  BarChart3,
  Zap,
  RefreshCw,
  Clock,
  Shield,
  TrendingDown
} from 'lucide-react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ScatterChart,
  Scatter
} from 'recharts';

interface BatchResult {
  cve_id: string;
  risk_score: number;
  priority: string;
  timeline_days: number;
  explanation: string;
  status: string;
  error?: string;
  components: Record<string, any>;
}

interface AIInsights {
  trends?: {
    current_avg_risk: number;
    risk_volatility: number;
    high_risk_count: number;
    medium_risk_count: number;
    low_risk_count: number;
    trend_direction: string;
    confidence_score: number;
    predictions?: number[];
  };
  anomalies?: {
    anomaly_count: number;
    anomaly_percentage: number;
    anomalous_vulnerabilities: any[];
    total_analyzed: number;
    anomaly_scores?: number[];
  };
  recommendations?: {
    recommendations: Array<{
      type: string;
      title: string;
      description: string;
      priority: string;
      action_items: string[];
    }>;
    summary: {
      total_recommendations: number;
      critical_count: number;
      high_count: number;
      medium_count: number;
    };
  };
  modelMetrics?: {
    mse: number;
    r2_score: number;
    training_samples: number;
    test_samples: number;
  };
}

const AIInsightsPage: React.FC = () => {
  const [batchResults, setBatchResults] = useState<BatchResult[]>([]);
  const [aiInsights, setAiInsights] = useState<AIInsights>({});
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'trends' | 'anomalies' | 'recommendations' | 'training'>('trends');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [comprehensiveAnalysis, setComprehensiveAnalysis] = useState(false);

  // Load batch results from localStorage
  useEffect(() => {
    const savedResults = localStorage.getItem('vulnrisk_batch_results');
    if (savedResults) {
      try {
        const results = JSON.parse(savedResults);
        setBatchResults(results);
      } catch (err) {
        console.error('Error loading saved results:', err);
      }
    }
  }, []);

  // Auto-refresh data every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      const savedResults = localStorage.getItem('vulnrisk_batch_results');
      if (savedResults) {
        try {
          const results = JSON.parse(savedResults);
          setBatchResults(results);
        } catch (err) {
          console.error('Error refreshing results:', err);
        }
      }
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const trainAIModel = async () => {
    if (batchResults.length < 10) {
      setError('Insufficient data for AI training. Please process at least 10 vulnerabilities first.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/ai/train-model`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ data: batchResults }),
      });

      if (!response.ok) {
        throw new Error('AI model training failed');
      }

      const data = await response.json();
      setAiInsights(prev => ({
        ...prev,
        modelMetrics: data.model_metrics
      }));
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI model training failed');
    } finally {
      setIsLoading(false);
    }
  };

  const predictTrends = async () => {
    if (batchResults.length === 0) {
      setError('No data available for trend prediction. Please process vulnerabilities first.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/ai/predict-trends`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ data: batchResults }),
      });

      if (!response.ok) {
        throw new Error('Trend prediction failed');
      }

      const data = await response.json();
      setAiInsights(prev => ({
        ...prev,
        trends: {
          ...data.trends,
          predictions: data.predictions
        }
      }));
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Trend prediction failed');
    } finally {
      setIsLoading(false);
    }
  };

  const detectAnomalies = async () => {
    if (batchResults.length === 0) {
      setError('No data available for anomaly detection. Please process vulnerabilities first.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/ai/detect-anomalies`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ data: batchResults }),
      });

      if (!response.ok) {
        throw new Error('Anomaly detection failed');
      }

      const data = await response.json();
      setAiInsights(prev => ({
        ...prev,
        anomalies: {
          ...data,
          anomaly_scores: data.anomaly_scores
        }
      }));
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Anomaly detection failed');
    } finally {
      setIsLoading(false);
    }
  };

  const generateRecommendations = async () => {
    if (batchResults.length === 0) {
      setError('No data available for recommendations. Please process vulnerabilities first.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/ai/recommendations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ data: batchResults }),
      });

      if (!response.ok) {
        throw new Error('Recommendation generation failed');
      }

      const data = await response.json();
      setAiInsights(prev => ({
        ...prev,
        recommendations: data
      }));
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Recommendation generation failed');
    } finally {
      setIsLoading(false);
    }
  };

  const runComprehensiveAnalysis = async () => {
    if (batchResults.length === 0) {
      setError('No data available for analysis. Please process vulnerabilities first.');
      return;
    }

    setIsLoading(true);
    setError(null);
    setComprehensiveAnalysis(true);

    try {
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/ai/comprehensive-analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ data: batchResults }),
      });

      if (!response.ok) {
        throw new Error('Comprehensive analysis failed');
      }

      const data = await response.json();
      
      // Update all AI insights at once
      setAiInsights({
        trends: data.trends,
        anomalies: data.anomalies,
        recommendations: data.recommendations,
        modelMetrics: aiInsights.modelMetrics // Keep existing model metrics
      });
      
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Comprehensive analysis failed');
    } finally {
      setIsLoading(false);
      setComprehensiveAnalysis(false);
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority.toLowerCase()) {
      case 'critical':
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 border-red-200 dark:border-red-700 hover:bg-red-200 dark:hover:bg-red-800';
      case 'high':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200 border-orange-200 dark:border-orange-700 hover:bg-orange-200 dark:hover:bg-orange-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 border-yellow-200 dark:border-yellow-700 hover:bg-yellow-200 dark:hover:bg-yellow-800';
      case 'low':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 border-blue-200 dark:border-blue-700 hover:bg-blue-200 dark:hover:bg-blue-800';
      case 'informational':
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200 border-gray-200 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-700';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200 border-gray-200 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-700';
    }
  };

  // Prepare chart data
  const prepareRiskDistributionData = () => {
    const distribution = {
      'Critical (8-10)': 0,
      'High (6-7.9)': 0,
      'Medium (4-5.9)': 0,
      'Low (0-3.9)': 0
    };

    batchResults.forEach(result => {
      const score = result.risk_score;
      if (score >= 8) distribution['Critical (8-10)']++;
      else if (score >= 6) distribution['High (6-7.9)']++;
      else if (score >= 4) distribution['Medium (4-5.9)']++;
      else distribution['Low (0-3.9)']++;
    });

    return Object.entries(distribution).map(([name, value]) => ({ name, value }));
  };

  const prepareTimelineData = () => {
    const timelineCounts = {
      '1 Day': 0,
      '7 Days': 0,
      '30 Days': 0,
      '180 Days': 0
    };

    batchResults.forEach(result => {
      const days = result.timeline_days;
      if (days <= 1) timelineCounts['1 Day']++;
      else if (days <= 7) timelineCounts['7 Days']++;
      else if (days <= 30) timelineCounts['30 Days']++;
      else timelineCounts['180 Days']++;
    });

    return Object.entries(timelineCounts).map(([name, value]) => ({ name, value }));
  };

  const prepareTrendData = () => {
    if (!aiInsights.trends?.predictions) return [];
    
    return batchResults.map((result, index) => ({
      cve: result.cve_id,
      actual: result.risk_score,
      predicted: aiInsights.trends!.predictions![index] || 0,
      index
    }));
  };

  const prepareAnomalyData = () => {
    if (!aiInsights.anomalies?.anomaly_scores) return [];
    
    return batchResults.map((result, index) => ({
      cve: result.cve_id,
      risk_score: result.risk_score,
      anomaly_score: aiInsights.anomalies!.anomaly_scores![index] || 0,
      is_anomaly: aiInsights.anomalies!.anomalous_vulnerabilities?.some(
        (v: any) => v.cve_id === result.cve_id
      ) || false
    }));
  };

  const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e'];

  return (
    <main className="container mx-auto px-4 py-8">
      {/* Demo Banner */}
      <div className="bg-purple-50 border border-purple-200 rounded-lg p-4 mb-6">
        <div className="flex items-start space-x-3">
          <div className="flex-shrink-0">
            <Brain className="h-5 w-5 text-purple-600" />
          </div>
          <div className="flex-1">
            <div className="flex items-center space-x-2 mb-2">
              <h3 className="text-sm font-medium text-purple-900">AI-Powered Risk Intelligence Demo</h3>
              <Badge variant="secondary" className="bg-purple-100 text-purple-800 text-xs">AI Demo</Badge>
            </div>
            <p className="text-sm text-purple-700 mb-2">
              Experience our AI-driven vulnerability analysis and risk prediction capabilities. 
              This demo showcases the future of intelligent security assessment.
            </p>
            <p className="text-xs text-purple-600">
              🤖 This is a demonstration of AI features. Real AI models and predictions will be available in upcoming releases.
            </p>
          </div>
        </div>
      </div>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Powerful Insights</h1>
            <p className="text-gray-600 mt-2">
              Machine learning-driven vulnerability analysis and predictive risk modeling
            </p>
          </div>
                      <div className="flex items-center space-x-2">
              {lastUpdated && (
                <div className="flex items-center text-sm text-gray-500">
                  <Clock className="h-4 w-4 mr-1" />
                  Last updated: {lastUpdated.toLocaleTimeString()}
                </div>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const savedResults = localStorage.getItem('vulnrisk_batch_results');
                  if (savedResults) {
                    setBatchResults(JSON.parse(savedResults));
                    setLastUpdated(new Date());
                  }
                }}
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              {batchResults.length >= 5 && (
                <Button
                  onClick={runComprehensiveAnalysis}
                  disabled={isLoading}
                  className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white"
                >
                  {comprehensiveAnalysis ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Running Analysis...
                    </>
                  ) : (
                    <>
                      <Brain className="h-4 w-4 mr-2" />
                      Run All Analysis
                    </>
                  )}
                </Button>
              )}
            </div>
        </div>

        {/* Data Summary Cards */}
        {batchResults.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center">
                  <Shield className="h-8 w-8 text-blue-600 mr-3" />
                  <div>
                    <div className="text-2xl font-bold text-gray-900">{batchResults.length}</div>
                    <p className="text-sm text-gray-600">Total Vulnerabilities</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center">
                  <TrendingUp className="h-8 w-8 text-orange-600 mr-3" />
                  <div>
                    <div className="text-2xl font-bold text-gray-900">
                      {(batchResults.reduce((sum, r) => sum + r.risk_score, 0) / batchResults.length).toFixed(1)}
                    </div>
                    <p className="text-sm text-gray-600">Average Risk Score</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center">
                  <AlertTriangle className="h-8 w-8 text-red-600 mr-3" />
                  <div>
                    <div className="text-2xl font-bold text-gray-900">
                      {batchResults.filter(r => r.risk_score >= 7).length}
                    </div>
                    <p className="text-sm text-gray-600">High Risk Vulns</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center">
                  <Activity className="h-8 w-8 text-green-600 mr-3" />
                  <div>
                    <div className="text-2xl font-bold text-gray-900">
                      {batchResults.filter(r => r.timeline_days <= 7).length}
                    </div>
                    <p className="text-sm text-gray-600">Urgent Timeline</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* AI Analysis Summary Dashboard */}
        {aiInsights.trends && aiInsights.anomalies && aiInsights.recommendations && (
          <Card className="border-2 border-purple-200 bg-gradient-to-r from-purple-50 to-blue-50">
            <CardHeader>
              <CardTitle className="flex items-center text-purple-800">
                <Brain className="h-6 w-6 mr-2" />
                AI Analysis Summary Dashboard
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">
                    {aiInsights.trends.trend_direction === 'increasing' ? '↗️' : '↘️'}
                  </div>
                  <p className="text-sm text-gray-600">Risk Trend</p>
                  <p className="text-xs text-gray-500 capitalize">{aiInsights.trends.trend_direction}</p>
                </div>
                
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-600">
                    {aiInsights.anomalies.anomaly_count}
                  </div>
                  <p className="text-sm text-gray-600">Anomalies</p>
                  <p className="text-xs text-gray-500">{aiInsights.anomalies.anomaly_percentage.toFixed(1)}% of total</p>
                </div>
                
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">
                    {aiInsights.recommendations.summary.total_recommendations}
                  </div>
                  <p className="text-sm text-gray-600">Recommendations</p>
                  <p className="text-xs text-gray-500">{aiInsights.recommendations.summary.critical_count} critical</p>
                </div>
                
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">
                    {(aiInsights.trends.confidence_score * 100).toFixed(0)}%
                  </div>
                  <p className="text-sm text-gray-600">AI Confidence</p>
                  <p className="text-xs text-gray-500">Model accuracy</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Main AI Analytics Card */}
        {batchResults.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Brain className="h-6 w-6 mr-2 text-purple-600" />
                AI Analytics Dashboard
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Tab Navigation */}
              <div className="flex flex-wrap gap-2">
                <Button
                  variant={activeTab === 'trends' ? 'default' : 'outline'}
                  onClick={() => setActiveTab('trends')}
                  className="flex items-center"
                >
                  <TrendingUp className="mr-2 h-4 w-4" />
                  Risk Trends
                </Button>
                <Button
                  variant={activeTab === 'anomalies' ? 'default' : 'outline'}
                  onClick={() => setActiveTab('anomalies')}
                  className="flex items-center"
                >
                  <AlertTriangle className="mr-2 h-4 w-4" />
                  Anomaly Detection
                </Button>
                <Button
                  variant={activeTab === 'recommendations' ? 'default' : 'outline'}
                  onClick={() => setActiveTab('recommendations')}
                  className="flex items-center"
                >
                  <Lightbulb className="mr-2 h-4 w-4" />
                  Smart Recommendations
                </Button>
                <Button
                  variant={activeTab === 'training' ? 'default' : 'outline'}
                  onClick={() => setActiveTab('training')}
                  className="flex items-center"
                >
                  <Target className="mr-2 h-4 w-4" />
                  Model Training
                </Button>
              </div>

              {/* Tab Content */}
              <div className="space-y-6">
                {activeTab === 'trends' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-semibold">Risk Trend Prediction</h3>
                      <Button 
                        onClick={predictTrends}
                        disabled={isLoading}
                        className="bg-blue-600 hover:bg-blue-700"
                      >
                        {isLoading ? 'Analyzing...' : 'Predict Trends'}
                      </Button>
                    </div>
                    
                    {aiInsights.trends && (
                      <div className="space-y-6">
                        {/* Trend Metrics */}
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-blue-600">
                                {aiInsights.trends.current_avg_risk.toFixed(2)}
                              </div>
                              <p className="text-sm text-gray-600">Average Risk Score</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-orange-600">
                                {aiInsights.trends.high_risk_count}
                              </div>
                              <p className="text-sm text-gray-600">High Risk Count</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="flex items-center">
                                <div className="text-2xl font-bold text-green-600">
                                  {aiInsights.trends.trend_direction}
                                </div>
                                {aiInsights.trends.trend_direction === 'increasing' ? (
                                  <TrendingUp className="h-5 w-5 text-red-500 ml-2" />
                                ) : (
                                  <TrendingDown className="h-5 w-5 text-green-500 ml-2" />
                                )}
                              </div>
                              <p className="text-sm text-gray-600">Trend Direction</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-purple-600">
                                {(aiInsights.trends.confidence_score * 100).toFixed(1)}%
                              </div>
                              <p className="text-sm text-gray-600">Confidence Score</p>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Risk Distribution Chart */}
                        <Card>
                          <CardHeader>
                            <CardTitle>Risk Score Distribution</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <ResponsiveContainer width="100%" height={300}>
                              <PieChart>
                                <Pie
                                  data={prepareRiskDistributionData()}
                                  cx="50%"
                                  cy="50%"
                                  labelLine={false}
                                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                                  outerRadius={80}
                                  fill="#8884d8"
                                  dataKey="value"
                                >
                                  {prepareRiskDistributionData().map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                  ))}
                                </Pie>
                                <Tooltip />
                                <Legend />
                              </PieChart>
                            </ResponsiveContainer>
                          </CardContent>
                        </Card>

                        {/* Timeline Distribution Chart */}
                        <Card>
                          <CardHeader>
                            <CardTitle>Remediation Timeline Distribution</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <ResponsiveContainer width="100%" height={300}>
                              <BarChart data={prepareTimelineData()}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="name" />
                                <YAxis />
                                <Tooltip />
                                <Bar dataKey="value" fill="#3b82f6" />
                              </BarChart>
                            </ResponsiveContainer>
                          </CardContent>
                        </Card>

                        {/* Prediction vs Actual Chart */}
                        {aiInsights.trends.predictions && (
                          <Card>
                            <CardHeader>
                              <CardTitle>Predicted vs Actual Risk Scores</CardTitle>
                            </CardHeader>
                            <CardContent>
                              <ResponsiveContainer width="100%" height={300}>
                                <ScatterChart>
                                  <CartesianGrid strokeDasharray="3 3" />
                                  <XAxis dataKey="actual" name="Actual Risk Score" />
                                  <YAxis dataKey="predicted" name="Predicted Risk Score" />
                                  <Tooltip />
                                  <Legend />
                                  <Scatter dataKey="predicted" fill="#3b82f6" />
                                </ScatterChart>
                              </ResponsiveContainer>
                            </CardContent>
                          </Card>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'anomalies' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-semibold">Anomaly Detection</h3>
                      <Button 
                        onClick={detectAnomalies}
                        disabled={isLoading}
                        className="bg-orange-600 hover:bg-orange-700"
                      >
                        {isLoading ? 'Detecting...' : 'Detect Anomalies'}
                      </Button>
                    </div>
                    
                    {aiInsights.anomalies && (
                      <div className="space-y-6">
                        {/* Anomaly Metrics */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-red-600">
                                {aiInsights.anomalies.anomaly_count}
                              </div>
                              <p className="text-sm text-gray-600">Anomalies Detected</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-orange-600">
                                {aiInsights.anomalies.anomaly_percentage.toFixed(1)}%
                              </div>
                              <p className="text-sm text-gray-600">Anomaly Percentage</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-blue-600">
                                {aiInsights.anomalies.total_analyzed}
                              </div>
                              <p className="text-sm text-gray-600">Total Analyzed</p>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Anomaly Score Distribution */}
                        {aiInsights.anomalies.anomaly_scores && (
                          <Card>
                            <CardHeader>
                              <CardTitle>Anomaly Score Distribution</CardTitle>
                            </CardHeader>
                            <CardContent>
                              <ResponsiveContainer width="100%" height={300}>
                                <AreaChart data={prepareAnomalyData()}>
                                  <CartesianGrid strokeDasharray="3 3" />
                                  <XAxis dataKey="cve" />
                                  <YAxis />
                                  <Tooltip />
                                  <Area 
                                    type="monotone" 
                                    dataKey="anomaly_score" 
                                    stroke="#ef4444" 
                                    fill="#fecaca" 
                                  />
                                </AreaChart>
                              </ResponsiveContainer>
                            </CardContent>
                          </Card>
                        )}
                        
                        {/* Anomalous Vulnerabilities List */}
                        {aiInsights.anomalies.anomalous_vulnerabilities.length > 0 && (
                          <Card>
                            <CardHeader>
                              <CardTitle>Anomalous Vulnerabilities</CardTitle>
                            </CardHeader>
                            <CardContent>
                              <div className="space-y-2">
                                {aiInsights.anomalies.anomalous_vulnerabilities.slice(0, 10).map((vuln: any, index: number) => (
                                  <div key={index} className="flex items-center justify-between p-3 bg-red-50 rounded-lg border border-red-200">
                                    <div className="flex items-center space-x-3">
                                      <AlertTriangle className="h-5 w-5 text-red-600" />
                                      <span className="font-mono text-sm font-semibold">{vuln.cve_id}</span>
                                      <span className="text-sm text-gray-600">Risk: {vuln.risk_score?.toFixed(2) || 'N/A'}</span>
                                    </div>
                                    <Badge className="bg-red-100 text-red-800">
                                      Anomaly
                                    </Badge>
                                  </div>
                                ))}
                              </div>
                            </CardContent>
                          </Card>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'recommendations' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-semibold">Intelligent Recommendations</h3>
                      <Button 
                        onClick={generateRecommendations}
                        disabled={isLoading}
                        className="bg-green-600 hover:bg-green-700"
                      >
                        {isLoading ? 'Generating...' : 'Generate Recommendations'}
                      </Button>
                    </div>
                    
                    {aiInsights.recommendations && (
                      <div className="space-y-6">
                        {/* Recommendation Summary */}
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-blue-600">
                                {aiInsights.recommendations.summary.total_recommendations}
                              </div>
                              <p className="text-sm text-gray-600">Total Recommendations</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-red-600">
                                {aiInsights.recommendations.summary.critical_count}
                              </div>
                              <p className="text-sm text-gray-600">Critical</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-orange-600">
                                {aiInsights.recommendations.summary.high_count}
                              </div>
                              <p className="text-sm text-gray-600">High Priority</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-yellow-600">
                                {aiInsights.recommendations.summary.medium_count}
                              </div>
                              <p className="text-sm text-gray-600">Medium Priority</p>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Recommendation Priority Chart */}
                        <Card>
                          <CardHeader>
                            <CardTitle>Recommendation Priority Distribution</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <ResponsiveContainer width="100%" height={300}>
                              <BarChart data={[
                                { priority: 'Critical', count: aiInsights.recommendations.summary.critical_count },
                                { priority: 'High', count: aiInsights.recommendations.summary.high_count },
                                { priority: 'Medium', count: aiInsights.recommendations.summary.medium_count }
                              ]}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="priority" />
                                <YAxis />
                                <Tooltip />
                                <Bar dataKey="count" fill="#22c55e" />
                              </BarChart>
                            </ResponsiveContainer>
                          </CardContent>
                        </Card>
                        
                        {/* Detailed Recommendations */}
                        <div className="space-y-4">
                          {aiInsights.recommendations.recommendations.map((rec: any, index: number) => (
                            <Card key={index}>
                              <CardHeader>
                                <div className="flex items-center justify-between">
                                  <CardTitle className="text-lg">{rec.title}</CardTitle>
                                  <Badge className={getPriorityColor(rec.priority)}>
                                    {rec.priority}
                                  </Badge>
                                </div>
                              </CardHeader>
                              <CardContent>
                                <p className="text-gray-600 mb-4">{rec.description}</p>
                                <div className="space-y-2">
                                  <h4 className="font-semibold text-sm">Action Items:</h4>
                                  <ul className="list-disc list-inside space-y-1 text-sm text-gray-700">
                                    {rec.action_items.map((item: string, itemIndex: number) => (
                                      <li key={itemIndex}>{item}</li>
                                    ))}
                                  </ul>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'training' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-semibold">Model Training</h3>
                      <Button 
                        onClick={trainAIModel}
                        disabled={isLoading || batchResults.length < 10}
                        className="bg-purple-600 hover:bg-purple-700"
                      >
                        {isLoading ? 'Training...' : 'Train Model'}
                      </Button>
                    </div>
                    
                    {aiInsights.modelMetrics && (
                      <div className="space-y-6">
                        {/* Model Metrics */}
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-blue-600">
                                {aiInsights.modelMetrics.r2_score.toFixed(3)}
                              </div>
                              <p className="text-sm text-gray-600">R² Score</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-green-600">
                                {aiInsights.modelMetrics.training_samples}
                              </div>
                              <p className="text-sm text-gray-600">Training Samples</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-orange-600">
                                {aiInsights.modelMetrics.test_samples}
                              </div>
                              <p className="text-sm text-gray-600">Test Samples</p>
                            </CardContent>
                          </Card>
                          
                          <Card>
                            <CardContent className="p-4">
                              <div className="text-2xl font-bold text-purple-600">
                                {aiInsights.modelMetrics.mse.toFixed(3)}
                              </div>
                              <p className="text-sm text-gray-600">Mean Squared Error</p>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Model Performance Chart */}
                        <Card>
                          <CardHeader>
                            <CardTitle>Model Performance Metrics</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <ResponsiveContainer width="100%" height={300}>
                              <BarChart data={[
                                { metric: 'R² Score', value: aiInsights.modelMetrics.r2_score },
                                { metric: 'MSE', value: aiInsights.modelMetrics.mse }
                              ]}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="metric" />
                                <YAxis />
                                <Tooltip />
                                <Bar dataKey="value" fill="#8b5cf6" />
                              </BarChart>
                            </ResponsiveContainer>
                          </CardContent>
                        </Card>
                      </div>
                    )}
                    
                    {batchResults.length < 10 && (
                      <Alert>
                        <AlertDescription>
                          At least 10 vulnerabilities are required to train the AI model. 
                          Currently have {batchResults.length} vulnerabilities.
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Error Display */}
        {error && (
          <Alert>
            <AlertDescription className="text-red-600">{error}</AlertDescription>
          </Alert>
        )}

        {/* Loading State */}
        {isLoading && (
          <Card>
            <CardContent className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              <span className="ml-2">Processing AI analysis...</span>
            </CardContent>
          </Card>
        )}

        {/* No Data State */}
        {!batchResults.length && (
          <Card>
            <CardContent className="py-8 text-center">
              <div className="text-gray-500">
                <Brain className="mx-auto h-12 w-12 mb-4 text-gray-400" />
                <p className="text-lg mb-2">No data available for AI analysis</p>
                <p className="text-sm">
                  Upload and process vulnerabilities in the Batch Processing section to enable powerful insights
                </p>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </main>
  );
};

export default AIInsightsPage; 