import React, { useState } from 'react';
import { Card, CardContent } from './card';
import { Button } from './button';
import { Badge } from './badge';

interface AssetCriticalityGuideProps {
  value: number;
  onChange: (value: number) => void;
}

export const AssetCriticalityGuide: React.FC<AssetCriticalityGuideProps> = ({ value, onChange }) => {
  const [showGuide, setShowGuide] = useState(false);

  const criticalityLevels = [
    {
      level: 10,
      name: "Mission Critical",
      description: "Payment systems, authentication servers, core business applications",
      examples: "Payment gateway, Active Directory, Primary database",
      impact: "Business shutdown if compromised",
      color: "bg-red-100 text-red-800"
    },
    {
      levelRange: [8, 9],
      name: "High Business Impact", 
      description: "Customer databases, core services, revenue-generating systems",
      examples: "Customer CRM, E-commerce platform, API gateway",
      impact: "Significant revenue/reputation loss",
      color: "bg-orange-100 text-orange-800"
    },
    {
      levelRange: [6, 7],
      name: "Important Operations",
      description: "Internal tools, reporting systems, operational applications", 
      examples: "HR systems, Business intelligence, Monitoring tools",
      impact: "Operational disruption, productivity loss",
      color: "bg-yellow-100 text-yellow-800"
    },
    {
      levelRange: [4, 5],
      name: "Standard Operations",
      description: "Development environments, testing systems, non-critical tools",
      examples: "Dev/test servers, Build systems, Internal wikis", 
      impact: "Minor operational impact",
      color: "bg-blue-100 text-blue-800"
    },
    {
      levelRange: [1, 3],
      name: "Low Impact",
      description: "Documentation, archived systems, deprecated applications",
      examples: "Static websites, Legacy systems, Archive storage",
      impact: "Minimal business impact", 
      color: "bg-gray-100 text-gray-800"
    }
  ];

  const getCurrentLevel = () => {
    if (value === 10) return criticalityLevels[0];
    if (value >= 8) return criticalityLevels[1]; 
    if (value >= 6) return criticalityLevels[2];
    if (value >= 4) return criticalityLevels[3];
    return criticalityLevels[4];
  };

  const currentLevel = getCurrentLevel();

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="block text-sm font-medium">
          Asset Criticality: {value}
        </label>
        <Button 
          variant="outline" 
          size="sm" 
          onClick={() => setShowGuide(!showGuide)}
        >
          {showGuide ? 'Hide' : 'Show'} Guide
        </Button>
      </div>
      
      <div className="space-y-2">
        <input
          type="range"
          min={1}
          max={10}
          value={value}
          onChange={(e) => onChange(parseInt(e.target.value))}
          className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
          aria-label={`Asset Criticality Level: ${value}`}
        />
        
        <div className="flex justify-between text-xs text-gray-500">
          <span>Low (1)</span>
          <span>Medium (5)</span>
          <span>Critical (10)</span>
        </div>
      </div>

      {/* Current Selection Display */}
      <div className="flex items-center space-x-2">
        <Badge className={currentLevel.color}>
          {currentLevel.name}
        </Badge>
        <span className="text-sm text-gray-600">{currentLevel.description}</span>
      </div>

      {/* Detailed Guide */}
      {showGuide && (
        <Card className="mt-4">
          <CardContent className="p-4">
            <h4 className="font-semibold mb-3">Asset Criticality Reference Guide</h4>
            <div className="space-y-3">
              {criticalityLevels.map((level, index) => {
                const isSelected = level.level ? value === level.level : 
                  (level.levelRange && value >= level.levelRange[0] && value <= level.levelRange[1]);
                const displayLevel = level.level || `${level.levelRange![0]}-${level.levelRange![1]}`;
                const clickValue = level.level || level.levelRange![1];
                
                return (
                  <div 
                    key={index}
                    className={`p-3 rounded-lg border-2 cursor-pointer transition-all ${
                      isSelected ? 'border-blue-500 bg-blue-50' : 'border-gray-200'
                    }`}
                    onClick={() => onChange(clickValue)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <Badge className={level.color}>Level {displayLevel}</Badge>
                        <span className="font-medium">{level.name}</span>
                      </div>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{level.description}</p>
                    <p className="text-xs text-gray-500 mb-1">
                      <strong>Examples:</strong> {level.examples}
                    </p>
                    <p className="text-xs text-gray-500">
                      <strong>Impact if compromised:</strong> {level.impact}
                    </p>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
