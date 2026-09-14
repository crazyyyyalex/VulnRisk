import { API_ENDPOINTS } from "../config/api";
import React, { useState, useEffect } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Badge } from '../components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { 
  Plus, 
  Edit, 
  Trash2, 
  RotateCcw, 
  Eye, 
  EyeOff, 
  CheckCircle, 
  XCircle, 
  AlertTriangle,
  Download,
  Activity,
  Shield,
  Key,
  RefreshCw
} from 'lucide-react';

interface APIKey {
  id: string;
  customer_id: string;
  key_type: 'nvd' | 'epss' | 'cisa_kev' | 'custom';
  key_name: string;
  status: 'active' | 'inactive' | 'expired' | 'revoked';
  created_at: string;
  updated_at: string;
  expires_at?: string;
  last_used_at?: string;
  usage_count: number;
  rate_limit?: number;
  metadata: Record<string, any>;
}

interface APIKeyUsageStats {
  key_id: string;
  key_name: string;
  key_type: string;
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  last_used?: string;
  average_response_time?: number;
  error_rate: number;
}

interface APIKeyAuditLog {
  id: string;
  customer_id: string;
  key_id: string;
  action: string;
  timestamp: string;
  ip_address?: string;
  user_agent?: string;
  details: Record<string, any>;
}

const APIKeyManagementPage: React.FC = () => {
  const { isAuthenticated, loginWithRedirect, getAccessTokenSilently } = useAuth0();
  const [apiKeys, setApiKeys] = useState<APIKey[]>([]);
  const [usageStats, setUsageStats] = useState<Record<string, APIKeyUsageStats>>({});
  const [auditLogs, setAuditLogs] = useState<APIKeyAuditLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showKeyValue, setShowKeyValue] = useState<Record<string, boolean>>({});
  
  // Form states
  const [newKeyForm, setNewKeyForm] = useState({
    key_type: 'nvd' as const,
    key_name: '',
    api_key_value: '',
    expires_at: '',
    rate_limit: ''
  });
  
  const [validationResult, setValidationResult] = useState<{
    is_valid: boolean;
    error_message?: string;
  } | null>(null);

  useEffect(() => {
    if (isAuthenticated) {
      loadAPIKeys();
      loadAuditLogs();
    }
  }, [isAuthenticated]);

  const loadAPIKeys = async () => {
    if (!isAuthenticated) return;
    
    try {
      const token = await getAccessTokenSilently();
      const response = await fetch(API_ENDPOINTS.apiKeys(), {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (response.ok) {
        const keys = await response.json();
        setApiKeys(keys);
        
        // Load usage stats for each key
        for (const key of keys) {
          await loadUsageStats(key.id, token);
        }
      }
    } catch (error) {
      console.error('Failed to load API keys:', error);
    }
  };

  const loadUsageStats = async (keyId: string, token: string) => {
    try {
      const response = await fetch(API_ENDPOINTS.apiKeyStats(keyId), {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (response.ok) {
        const stats = await response.json();
        setUsageStats(prev => ({ ...prev, [keyId]: stats }));
      }
    } catch (error) {
      console.error(`Failed to load usage stats for key ${keyId}:`, error);
    }
  };

  const loadAuditLogs = async () => {
    if (!isAuthenticated) return;
    
    try {
      const token = await getAccessTokenSilently();
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/api-keys/audit-logs/all?limit=50`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (response.ok) {
        const logs = await response.json();
        setAuditLogs(logs);
      }
    } catch (error) {
      console.error('Failed to load audit logs:', error);
    }
  };

  const createAPIKey = async () => {
    if (!isAuthenticated) {
      await loginWithRedirect();
      return;
    }
    
    setLoading(true);
    try {
      const token = await getAccessTokenSilently();
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/api-keys/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          key_type: newKeyForm.key_type,
          key_name: newKeyForm.key_name,
          api_key_value: newKeyForm.api_key_value,
          expires_at: newKeyForm.expires_at || null,
          rate_limit: newKeyForm.rate_limit ? parseInt(newKeyForm.rate_limit) : null,
        }),
      });
      
      if (response.ok) {
        await loadAPIKeys();
        setShowCreateForm(false);
        setNewKeyForm({
          key_type: 'nvd',
          key_name: '',
          api_key_value: '',
          expires_at: '',
          rate_limit: ''
        });
      } else {
        const error = await response.json();
        alert(`Failed to create API key: ${error.detail}`);
      }
    } catch (error) {
      console.error('Failed to create API key:', error);
      alert('Failed to create API key');
    } finally {
      setLoading(false);
    }
  };

  const validateAPIKey = async () => {
    if (!isAuthenticated) return;
    
    try {
      const token = await getAccessTokenSilently();
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/api-keys/validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          key_type: newKeyForm.key_type,
          api_key_value: newKeyForm.api_key_value,
        }),
      });
      
      if (response.ok) {
        const result = await response.json();
        setValidationResult(result);
      }
    } catch (error) {
      console.error('Failed to validate API key:', error);
    }
  };

  const deleteAPIKey = async (keyId: string) => {
    if (!isAuthenticated) return;
    
    if (!confirm('Are you sure you want to delete this API key? This action cannot be undone.')) {
      return;
    }
    
    try {
      const token = await getAccessTokenSilently();
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/api-keys/${keyId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (response.ok) {
        await loadAPIKeys();
      } else {
        const error = await response.json();
        alert(`Failed to delete API key: ${error.detail}`);
      }
    } catch (error) {
      console.error('Failed to delete API key:', error);
      alert('Failed to delete API key');
    }
  };

  const rotateAPIKey = async (keyId: string, newKeyValue: string) => {
    if (!isAuthenticated) return;
    
    try {
      const token = await getAccessTokenSilently();
      const response = await fetch(`${API_ENDPOINTS.health().replace("/health", "")}/api/v1/api-keys/${keyId}/rotate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          new_api_key_value: newKeyValue,
          rotation_reason: 'Security rotation',
        }),
      });
      
      if (response.ok) {
        await loadAPIKeys();
        alert('API key rotated successfully');
      } else {
        const error = await response.json();
        alert(`Failed to rotate API key: ${error.detail}`);
      }
    } catch (error) {
      console.error('Failed to rotate API key:', error);
      alert('Failed to rotate API key');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-100 text-green-800';
      case 'inactive': return 'bg-gray-100 text-gray-800';
      case 'expired': return 'bg-red-100 text-red-800';
      case 'revoked': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getKeyTypeIcon = (keyType: string) => {
    switch (keyType) {
      case 'nvd': return <Shield className="w-4 h-4" />;
      case 'epss': return <Activity className="w-4 h-4" />;
      case 'cisa_kev': return <Key className="w-4 h-4" />;
      default: return <Key className="w-4 h-4" />;
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">API Key Management</h1>
          <p className="text-gray-600 mb-4">Please log in to manage your API keys.</p>
          <Button onClick={() => loginWithRedirect()}>Log In</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold">API Key Management</h1>
          <p className="text-gray-600">Manage your API keys for external services</p>
        </div>
        <Button onClick={() => setShowCreateForm(true)} className="flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Add API Key
        </Button>
      </div>

      <Tabs defaultValue="keys" className="space-y-6">
        <TabsList>
          <TabsTrigger value="keys">API Keys</TabsTrigger>
          <TabsTrigger value="audit">Audit Logs</TabsTrigger>
        </TabsList>

        <TabsContent value="keys" className="space-y-6">
          {/* API Keys List */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Key className="w-5 h-5" />
                Your API Keys
              </CardTitle>
            </CardHeader>
            <CardContent>
              {apiKeys.length === 0 ? (
                <div className="text-center py-8">
                  <Key className="w-12 h-12 mx-auto text-gray-400 mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No API keys yet</h3>
                  <p className="text-gray-600 mb-4">Get started by adding your first API key</p>
                  <Button onClick={() => setShowCreateForm(true)}>Add Your First Key</Button>
                </div>
              ) : (
                <div className="space-y-4">
                  {apiKeys.map((key) => (
                    <div key={key.id} className="border rounded-lg p-4 space-y-3">
                      <div className="flex justify-between items-start">
                        <div className="flex items-center gap-3">
                          {getKeyTypeIcon(key.key_type)}
                          <div>
                            <h3 className="font-medium">{key.key_name}</h3>
                            <p className="text-sm text-gray-600 capitalize">{key.key_type.replace('_', ' ')}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getStatusColor(key.status)}>
                            {key.status}
                          </Badge>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setShowKeyValue(prev => ({ ...prev, [key.id]: !prev[key.id] }))}
                          >
                            {showKeyValue[key.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </Button>
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <span className="text-gray-600">Created:</span>
                          <p>{new Date(key.created_at).toLocaleDateString()}</p>
                        </div>
                        <div>
                          <span className="text-gray-600">Usage Count:</span>
                          <p>{key.usage_count}</p>
                        </div>
                        <div>
                          <span className="text-gray-600">Last Used:</span>
                          <p>{key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}</p>
                        </div>
                        <div>
                          <span className="text-gray-600">Rate Limit:</span>
                          <p>{key.rate_limit ? `${key.rate_limit}/hour` : 'Unlimited'}</p>
                        </div>
                      </div>

                      {/* Usage Stats */}
                      {usageStats[key.id] && (
                        <div className="bg-gray-50 rounded p-3">
                          <h4 className="font-medium mb-2">Usage Statistics</h4>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                            <div>
                              <span className="text-gray-600">Total Requests:</span>
                              <p>{usageStats[key.id].total_requests}</p>
                            </div>
                            <div>
                              <span className="text-gray-600">Success Rate:</span>
                              <p>{((usageStats[key.id].successful_requests / usageStats[key.id].total_requests) * 100).toFixed(1)}%</p>
                            </div>
                            <div>
                              <span className="text-gray-600">Error Rate:</span>
                              <p>{(usageStats[key.id].error_rate * 100).toFixed(1)}%</p>
                            </div>
                            <div>
                              <span className="text-gray-600">Avg Response:</span>
                              <p>{usageStats[key.id].average_response_time ? `${usageStats[key.id].average_response_time.toFixed(2)}ms` : 'N/A'}</p>
                            </div>
                          </div>
                        </div>
                      )}

                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            const newKey = prompt('Enter new API key value:');
                            if (newKey) rotateAPIKey(key.id, newKey);
                          }}
                        >
                          <RotateCcw className="w-4 h-4 mr-1" />
                          Rotate
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => deleteAPIKey(key.id)}
                        >
                          <Trash2 className="w-4 h-4 mr-1" />
                          Delete
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="audit" className="space-y-6">
          {/* Audit Logs */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="w-5 h-5" />
                Audit Logs
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {auditLogs.map((log) => (
                  <div key={log.id} className="border rounded-lg p-4">
                    <div className="flex justify-between items-start">
                      <div>
                        <h4 className="font-medium">{log.action}</h4>
                        <p className="text-sm text-gray-600">{new Date(log.timestamp).toLocaleString()}</p>
                        {log.details && Object.keys(log.details).length > 0 && (
                          <div className="mt-2 text-sm">
                            <pre className="bg-gray-50 p-2 rounded text-xs overflow-x-auto">
                              {JSON.stringify(log.details, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                      <Badge variant="outline">{log.action}</Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create API Key Modal */}
      {showCreateForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold mb-4">Add New API Key</h2>
            
            <div className="space-y-4">
              <div>
                <Label htmlFor="key_type">API Key Type</Label>
                <select
                  id="key_type"
                  value={newKeyForm.key_type}
                  onChange={(e) => setNewKeyForm(prev => ({ ...prev, key_type: e.target.value as any }))}
                  className="w-full border rounded-md p-2"
                  aria-label="API Key Type"
                >
                  <option value="nvd">NVD (National Vulnerability Database)</option>
                  <option value="epss">EPSS (Exploit Prediction Scoring System)</option>
                  <option value="cisa_kev">CISA KEV (Known Exploited Vulnerabilities)</option>
                  <option value="custom">Custom</option>
                </select>
              </div>

              <div>
                <Label htmlFor="key_name">Key Name</Label>
                <Input
                  id="key_name"
                  value={newKeyForm.key_name}
                  onChange={(e) => setNewKeyForm(prev => ({ ...prev, key_name: e.target.value }))}
                  placeholder="e.g., Production NVD Key"
                />
              </div>

              <div>
                <Label htmlFor="api_key_value">API Key Value</Label>
                <Input
                  id="api_key_value"
                  type="password"
                  value={newKeyForm.api_key_value}
                  onChange={(e) => setNewKeyForm(prev => ({ ...prev, api_key_value: e.target.value }))}
                  placeholder="Enter your API key"
                />
              </div>

              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={validateAPIKey}
                  disabled={!newKeyForm.api_key_value}
                >
                  Validate Key
                </Button>
                {validationResult && (
                  <div className="flex items-center gap-2">
                    {validationResult.is_valid ? (
                      <CheckCircle className="w-4 h-4 text-green-600" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-600" />
                    )}
                    <span className={validationResult.is_valid ? 'text-green-600' : 'text-red-600'}>
                      {validationResult.is_valid ? 'Valid' : 'Invalid'}
                    </span>
                  </div>
                )}
              </div>

              {validationResult?.error_message && (
                <div className="text-red-600 text-sm">{validationResult.error_message}</div>
              )}

              <div>
                <Label htmlFor="expires_at">Expiration Date (Optional)</Label>
                <Input
                  id="expires_at"
                  type="datetime-local"
                  value={newKeyForm.expires_at}
                  onChange={(e) => setNewKeyForm(prev => ({ ...prev, expires_at: e.target.value }))}
                />
              </div>

              <div>
                <Label htmlFor="rate_limit">Rate Limit (requests/hour, Optional)</Label>
                <Input
                  id="rate_limit"
                  type="number"
                  value={newKeyForm.rate_limit}
                  onChange={(e) => setNewKeyForm(prev => ({ ...prev, rate_limit: e.target.value }))}
                  placeholder="e.g., 1000"
                />
              </div>
            </div>

            <div className="flex gap-2 mt-6">
              <Button onClick={createAPIKey} disabled={loading || !newKeyForm.key_name || !newKeyForm.api_key_value}>
                {loading ? 'Creating...' : 'Create API Key'}
              </Button>
              <Button variant="outline" onClick={() => setShowCreateForm(false)}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default APIKeyManagementPage; 