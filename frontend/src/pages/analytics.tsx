import React, { useState, useEffect } from 'react';
import { AnalyticsDashboard } from '../components/AnalyticsDashboard';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { useAuth0 } from '@auth0/auth0-react';
import { API_ENDPOINTS } from '../config/api';
import { BarChart3, Download, Upload, RefreshCw } from 'lucide-react';

interface BatchResult {
  cve_id: string;
  risk_score: number;
  priority: string;
  timeline_days: number;
  explanation: string;
  status: string;
  error?: string;
  components: Record<string, number>;
}

const AnalyticsPage: React.FC = () => {
  const { isAuthenticated, loginWithRedirect, getAccessTokenSilently } = useAuth0();
  const [analyticsData, setAnalyticsData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [batchResults, setBatchResults] = useState<BatchResult[]>([]);

  const generateAnalytics = async (results: BatchResult[]) => {
    if (results.length === 0) {
      setError('No batch results available. Please process some vulnerabilities first.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      // Before sending the analytics POST request, ensure each result has a 'components' field
      const sanitizedResults = results.map(result => ({
        ...result,
        components: result.components || {}, // Ensure 'components' is present and is an object
      }));

      const response = await fetch(API_ENDPOINTS.analytics(), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(sanitizedResults),
      });

      if (!response.ok) {
        throw new Error(`Analytics generation failed: ${response.status}`);
      }

      const data = await response.json();
      setAnalyticsData(data);
    } catch (err) {
      console.error('Analytics error:', err);
      setError(err instanceof Error ? err.message : 'Failed to generate analytics');
    } finally {
      setIsLoading(false);
    }
  };

  const generateReport = async (reportType: string) => {
    if (!isAuthenticated) {
      await loginWithRedirect();
      return;
    }
    if (batchResults.length === 0) {
      alert('No data available for report generation. Please process some vulnerabilities first.');
      return;
    }

    try {
      const token = await getAccessTokenSilently();
      const response = await fetch(API_ENDPOINTS.reports(), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          report_type: reportType,
          include_charts: true,
          include_details: true,
          filters: { data: batchResults }
        }),
      });

      if (!response.ok) {
        throw new Error(`Report generation failed: ${response.status}`);
      }

      const data = await response.json();
      if (!data.download_url) {
        alert('Report generated, but no download URL returned.');
        return;
      }
      // Download the file
      const downloadResp = await fetch(`${API_ENDPOINTS.health().replace('/health', '')}${data.download_url}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (!downloadResp.ok) {
        throw new Error('Failed to download the report file.');
      }
      const blob = await downloadResp.blob();
      // Determine file extension
      let ext = '';
      if (reportType === 'pdf') ext = '.pdf';
      else if (reportType === 'excel') ext = '.xlsx';
      else if (reportType === 'csv') ext = '.csv';
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnrisk-report${ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      alert('Report generated and downloaded successfully!');
    } catch (err) {
      console.error('Report generation error:', err);
      alert('Report generation or download failed. Please try again.');
    }
  };

  // Load batch results from localStorage or session storage
  useEffect(() => {
    const savedResults = localStorage.getItem('vulnrisk_batch_results');
    if (savedResults) {
      try {
        const results = JSON.parse(savedResults);
        setBatchResults(results);
        if (results.length > 0) {
          generateAnalytics(results);
        }
      } catch (err) {
        console.error('Error loading saved results:', err);
      }
    }
  }, []);

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Demo Banner */}
      <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 mb-6">
        <div className="flex items-start space-x-3">
          <div className="flex-shrink-0">
            <BarChart3 className="h-5 w-5 text-orange-600" />
          </div>
          <div className="flex-1">
            <div className="flex items-center space-x-2 mb-2">
              <h3 className="text-sm font-medium text-orange-900">Advanced Analytics Demo</h3>
              <Badge variant="secondary" className="bg-orange-100 text-orange-800 text-xs">Analytics Demo</Badge>
            </div>
            <p className="text-sm text-orange-700 mb-2">
              Explore comprehensive vulnerability analytics and reporting capabilities. 
              This demo shows advanced visualizations and trend analysis features.
            </p>
            <p className="text-xs text-orange-600">
              📊 This is a demonstration of analytics features. Real analytics data will be available in upcoming releases.
            </p>
          </div>
        </div>
      </div>

      {/* Data Status */}
      <Card>
        <CardHeader>
          <CardTitle>Data Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">
                {batchResults.length > 0 
                  ? `${batchResults.length} vulnerabilities processed`
                  : 'No batch data available'
                }
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Process vulnerabilities in the Batch Processing section to see analytics
              </p>
            </div>
            {batchResults.length > 0 && (
              <Button 
                onClick={() => generateAnalytics(batchResults)}
                disabled={isLoading}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {isLoading ? 'Generating...' : 'Refresh Analytics'}
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Report Generation */}
      {batchResults.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Generate Reports</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4">
              <Button 
                onClick={() => generateReport('pdf')}
                className="bg-red-600 hover:bg-red-700"
              >
                Generate PDF Report
              </Button>
              <Button 
                onClick={() => generateReport('excel')}
                className="bg-green-600 hover:bg-green-700"
              >
                Generate Excel Report
              </Button>
              <Button 
                onClick={() => generateReport('csv')}
                className="bg-blue-600 hover:bg-blue-700"
              >
                Generate CSV Report
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Analytics Dashboard */}
      {isLoading && (
        <Card>
          <CardContent className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2">Generating analytics...</span>
          </CardContent>
        </Card>
      )}

      {error && (
        <Card>
          <CardContent className="py-4">
            <div className="text-red-600">Error: {error}</div>
          </CardContent>
        </Card>
      )}

      {analyticsData && !isLoading && (
        <AnalyticsDashboard data={analyticsData} />
      )}

      {!analyticsData && !isLoading && batchResults.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center">
            <div className="text-gray-500">
              <p className="text-lg mb-2">No analytics data available</p>
              <p className="text-sm">
                Upload and process vulnerabilities in the Batch Processing section to generate analytics
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default AnalyticsPage; 