import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';
import { Bar, Pie } from 'react-chartjs-2';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface AnalyticsData {
  risk_distribution: {
    total_count: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    unknown_count: number;
    average_score: number;
    median_score: number;
    score_ranges: Record<string, number>;
  };
  asset_analysis: Array<{
    criticality_level: number;
    count: number;
    average_risk_score: number;
    internet_facing_count: number;
    internal_count: number;
  }>;
  top_critical_vulnerabilities: Array<{
    cve_id: string;
    risk_score: number;
    timeline_days: number;
    explanation: string;
  }>;
  processing_stats: {
    total_processed: number;
    successful_count: number;
    error_count: number;
    success_rate: number;
  };
}

interface AnalyticsDashboardProps {
  data: AnalyticsData;
}

export const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({ data }) => {
  // Risk Distribution Pie Chart
  const riskDistributionData = {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Unknown'],
    datasets: [
      {
        data: [
          data.risk_distribution.critical_count,
          data.risk_distribution.high_count,
          data.risk_distribution.medium_count,
          data.risk_distribution.low_count,
          data.risk_distribution.unknown_count,
        ],
        backgroundColor: [
          '#dc2626', // red
          '#ea580c', // orange
          '#d97706', // amber
          '#16a34a', // green
          '#6b7280', // gray
        ],
        borderWidth: 2,
        borderColor: '#ffffff',
      },
    ],
  };

  // Asset Criticality Bar Chart
  const assetAnalysisData = {
    labels: data.asset_analysis.map(asset => `Level ${asset.criticality_level}`),
    datasets: [
      {
        label: 'Average Risk Score',
        data: data.asset_analysis.map(asset => asset.average_risk_score),
        backgroundColor: '#3b82f6',
        borderColor: '#1d4ed8',
        borderWidth: 1,
      },
      {
        label: 'Count',
        data: data.asset_analysis.map(asset => asset.count),
        backgroundColor: '#10b981',
        borderColor: '#059669',
        borderWidth: 1,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top' as const,
      },
    },
  };

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Vulnerabilities</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{data.risk_distribution.total_count}</div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{data.risk_distribution.critical_count}</div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Average Risk Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{data.risk_distribution.average_score.toFixed(1)}</div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{data.processing_stats.success_rate.toFixed(1)}%</div>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Risk Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <Pie data={riskDistributionData} options={chartOptions} />
            </div>
          </CardContent>
        </Card>

        {/* Asset Analysis Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Asset Criticality Analysis</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <Bar data={assetAnalysisData} options={chartOptions} />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Top Critical Vulnerabilities */}
      <Card>
        <CardHeader>
          <CardTitle>Top Critical Vulnerabilities</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {data.top_critical_vulnerabilities.map((vuln, index) => (
              <div key={index} className="flex items-center justify-between p-4 bg-red-50 rounded-lg">
                <div className="flex-1">
                  <div className="font-semibold text-red-900">{vuln.cve_id}</div>
                  <div className="text-sm text-red-700">{vuln.explanation}</div>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-red-600">{vuln.risk_score.toFixed(1)}</div>
                  <div className="text-sm text-red-600">{vuln.timeline_days} days</div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}; 