import React, { useState, useEffect } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { FileUpload } from '../components/FileUpload';
import { ResultsTable } from '../components/ResultsTable';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Progress } from '../components/ui/progress';
import { API_ENDPOINTS } from '../config/api';
import { Upload, Download, Play, StopCircle, RefreshCw, Zap, BarChart3 } from 'lucide-react';

interface BatchResult {
  cve_id: string;
  risk_score: number;
  priority: string;
  timeline_days: number;
  explanation: string;
  status: string;
  error?: string;
}

const BatchPage: React.FC = () => {
  const { isAuthenticated, loginWithRedirect, getAccessTokenSilently } = useAuth0();
  const [isUploading, setIsUploading] = useState(false);
  const [results, setResults] = useState<BatchResult[]>([]);
  const [processingStats, setProcessingStats] = useState<{
    total: number;
    processed: number;
    success: number;
    error: number;
  } | null>(null);

  const handleFileUpload = async (file: File) => {
    if (!isAuthenticated) {
      await loginWithRedirect();
      return;
    }

    setIsUploading(true);
    setResults([]);
    setProcessingStats(null);

    try {
      const token = await getAccessTokenSilently();
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(API_ENDPOINTS.uploadCsv(), {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.status}`);
      }

      const data = await response.json();
      
      // Convert results to our format
      const batchResults: BatchResult[] = data.results.map((result: any) => ({
        cve_id: result.cve_id,
        risk_score: result.risk_score,
        priority: result.priority,
        timeline_days: result.timeline_days,
        explanation: result.explanation,
        status: result.status,
        error: result.error,
      }));

      setResults(batchResults);
      
      // Save results to localStorage for analytics
      localStorage.setItem('vulnrisk_batch_results', JSON.stringify(batchResults));
      
      // Calculate stats
      const total = batchResults.length;
      const success = batchResults.filter(r => r.status === 'success').length;
      const error = total - success;
      
      setProcessingStats({
        total,
        processed: total,
        success,
        error,
      });

    } catch (error) {
      console.error('Upload error:', error);
      alert('Error uploading file. Please try again.');
    } finally {
      setIsUploading(false);
    }
  };

  const clearResults = () => {
    setResults([]);
    setProcessingStats(null);
  };

  const exportResults = () => {
    if (results.length === 0) return;

    const csvContent = [
      'CVE_ID,Risk_Score,Priority,Timeline_Days,Explanation,Status',
      ...results.map(result => 
        `"${result.cve_id}",${result.risk_score},"${result.priority}",${result.timeline_days},"${result.explanation}","${result.status}"`
      )
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vulnrisk_batch_results.csv';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Demo Banner */}
      <div className="bg-indigo-50 border border-indigo-200 rounded-lg p-4 mb-6">
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
            <p className="text-xs text-indigo-600">
              ⚠️ This is a preview of the batch processing capabilities. Actual batch processing features will be available in upcoming releases.
            </p>
          </div>
        </div>
      </div>

      <div className="flex items-center space-x-4 mb-6">
        <div className="flex items-center space-x-2">
          <Zap className="h-6 w-6 text-primary-600" />
          <h1 className="text-2xl font-bold text-gray-900">Batch Risk Assessment</h1>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Section */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Upload className="h-5 w-5" />
                <span>Upload CSV File</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <FileUpload onFileUpload={handleFileUpload} isUploading={isUploading} />
            </CardContent>
          </Card>
        </div>

        {/* Stats Section */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <BarChart3 className="h-5 w-5" />
                <span>Processing Stats</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {processingStats ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-3 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-primary-600">{processingStats.total}</div>
                      <div className="text-sm text-gray-600">Total</div>
                    </div>
                    <div className="text-center p-3 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-success-600">{processingStats.success}</div>
                      <div className="text-sm text-gray-600">Success</div>
                    </div>
                  </div>
                  {processingStats.error > 0 && (
                    <div className="text-center p-3 bg-red-50 rounded-lg">
                      <div className="text-2xl font-bold text-red-600">{processingStats.error}</div>
                      <div className="text-sm text-gray-600">Errors</div>
                    </div>
                  )}
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Progress</span>
                      <span>{Math.round((processingStats.processed / processingStats.total) * 100)}%</span>
                    </div>
                    <Progress value={(processingStats.processed / processingStats.total) * 100} />
                  </div>
                </div>
              ) : (
                <div className="text-center text-gray-500 py-8">
                  <BarChart3 className="h-12 w-12 mx-auto mb-2 text-gray-300" />
                  <p>No processing stats available</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Results Section */}
      {results.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center space-x-2">
                <Download className="h-5 w-5" />
                <span>Results ({results.length})</span>
              </CardTitle>
              <div className="flex space-x-2">
                <Button onClick={exportResults}>
                  <Download className="h-4 w-4 mr-2" />
                  Export CSV
                </Button>
                <Button onClick={clearResults}>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Clear Results
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <ResultsTable results={results} />
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default BatchPage; 