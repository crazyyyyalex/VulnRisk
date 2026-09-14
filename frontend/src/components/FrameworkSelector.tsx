import React, { useState, useEffect } from 'react';
import { API_ENDPOINTS } from '../config/api';
import { apiCall } from '../lib/utils';

interface Framework {
  id: string;
  name: string;
  description: string;
}

interface FrameworkSelectorProps {
  selectedFramework: string;
  onFrameworkChange: (framework: string) => void;
}

export const FrameworkSelector: React.FC<FrameworkSelectorProps> = ({ 
  selectedFramework, 
  onFrameworkChange 
}) => {
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchFrameworks = async () => {
      try {
        const data = await apiCall(API_ENDPOINTS.frameworks());
        setFrameworks(data.frameworks);
      } catch (err) {
        setError('Failed to load frameworks');
      } finally {
        setLoading(false);
      }
    };

    fetchFrameworks();
  }, []);

  if (loading) {
    return <div className="text-gray-500">Loading frameworks...</div>;
  }

  if (error) {
    return <div className="text-red-500">{error}</div>;
  }

  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium mb-2">Risk Framework</label>
      <select
        value={selectedFramework}
        onChange={(e) => onFrameworkChange(e.target.value)}
        className="border border-gray-300 rounded px-3 py-2 w-full focus:outline-none focus:ring-2 focus:ring-blue-500"
        title="Risk Framework Selection"
      >
        {frameworks.map((framework) => (
          <option key={framework.id} value={framework.id}>
            {framework.name}
          </option>
        ))}
      </select>
      {frameworks.find(f => f.id === selectedFramework) && (
        <p className="text-sm text-gray-600 mt-1">
          {frameworks.find(f => f.id === selectedFramework)?.description}
        </p>
      )}
    </div>
  );
}; 