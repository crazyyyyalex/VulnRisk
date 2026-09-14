// API Configuration
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
export const API_GATEWAY_KEY = import.meta.env.VITE_API_GATEWAY_KEY || '';

export const apiUrl = (path: string) => `${API_BASE_URL}${path}`;

// API Authentication Headers
export const getAuthHeaders = () => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  // Add API Gateway key if available
  if (API_GATEWAY_KEY) {
    headers['X-API-Key'] = API_GATEWAY_KEY;
  }
  
  return headers;
};

// API Endpoints
export const API_ENDPOINTS = {
  // Core API
  health: () => apiUrl('/health'),
  
  // Risk Assessment
  score: () => apiUrl('/api/v1/score'),
  frameworks: () => apiUrl('/api/v1/frameworks'),
  
  // File Upload
  uploadCsv: () => apiUrl('/api/v1/upload-csv'),
  
  // API Key Management
  apiKeys: () => apiUrl('/api/v1/api-keys/'),
  apiKeyStats: (keyId: string) => apiUrl(`/api/v1/api-keys/${keyId}/stats`),
  apiKeyAuditLogs: () => apiUrl('/api/v1/api-keys/audit-logs/all?limit=50'),
  apiKeyValidate: () => apiUrl('/api/v1/api-keys/validate'),
  apiKeyRotate: (keyId: string) => apiUrl(`/api/v1/api-keys/${keyId}/rotate`),
  
  // Analytics
  analytics: () => apiUrl('/api/v1/analytics'),
  reports: () => apiUrl('/api/v1/reports'),
  
  // Scanner Integrations
  scanners: () => apiUrl('/api/v1/scanners'),
  scannerStatus: (scannerType: string) => apiUrl(`/api/v1/scanners/${scannerType}/status`),
  scannerScan: () => apiUrl('/api/v1/scanners/scan'),
  scannerMultiScan: () => apiUrl('/api/v1/scanners/multi-scan'),
  
  // AI Features
  aiTrainModel: () => apiUrl('/api/v1/ai/train-model'),
  aiPredictTrends: () => apiUrl('/api/v1/ai/predict-trends'),
  aiDetectAnomalies: () => apiUrl('/api/v1/ai/detect-anomalies'),
  aiRecommendations: () => apiUrl('/api/v1/ai/recommendations'),
  aiComprehensiveAnalysis: () => apiUrl('/api/v1/ai/comprehensive-analysis'),
  
  // Feature Flags
  features: () => apiUrl('/api/v1/config/features'),
  
  // FedRAMP Compliance
  fedrampAssess: () => apiUrl('/api/v1/fedramp/assess'),
  fedrampBatchAssess: () => apiUrl('/api/v1/fedramp/batch-assess'),
  fedrampComplianceReport: (orgName: string, days: number = 30) => apiUrl(`/api/v1/fedramp/compliance-report/${orgName}?days=${days}`),
  fedrampVDRAssess: () => apiUrl('/api/v1/fedramp/vdr/assess'),
  fedrampVDRFrameworkInfo: () => apiUrl('/api/v1/fedramp/vdr/framework-info'),
};

// Environment detection
export const isProduction = import.meta.env.VITE_ENVIRONMENT === 'production';
export const isDevelopment = import.meta.env.VITE_ENVIRONMENT === 'development'; 