"""
Feature Flags Configuration for VulnRisk

This module manages feature availability based on environment and configuration.
Features can be enabled/disabled per environment to control deployment.
"""

from enum import Enum
from typing import Dict, Any
import os
import logging

logger = logging.getLogger(__name__)

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class FeatureFlags:
    def __init__(self):
        self.environment = Environment(os.getenv("ENVIRONMENT", "development"))
        self.flags = self._load_flags()
        logger.info(f"Feature flags initialized for environment: {self.environment.value}")
        logger.info(f"Enabled features: {[k for k, v in self.flags.items() if v]}")
    
    def _load_flags(self) -> Dict[str, bool]:
        """Load feature flags based on environment"""
        return {
            # FedRAMP Features (experimental, not production-ready)
            "fedramp_compliance": self.environment != Environment.PRODUCTION,
            "fedramp_timeline": self.environment != Environment.PRODUCTION,
            "fedramp_audit_trail": self.environment != Environment.PRODUCTION,
            "fedramp_reporting": self.environment != Environment.PRODUCTION,
            
            # API Key Management (stable, always enabled)
            "customer_api_keys": True,
            "api_key_rotation": True,
            "api_key_analytics": True,
            
            # AI/ML Features (experimental in staging, dev only for training)
            "ai_risk_prediction": self.environment != Environment.PRODUCTION,
            "ai_anomaly_detection": self.environment != Environment.PRODUCTION,
            "ai_recommendations": self.environment != Environment.PRODUCTION,
            "model_training": self.environment == Environment.DEVELOPMENT,
            "model_versioning": self.environment != Environment.PRODUCTION,
            
            # Scanner Features (experimental)
            "scanner_integrations": self.environment != Environment.PRODUCTION,
            "multi_scanner": self.environment != Environment.PRODUCTION,
            "custom_scan_profiles": self.environment != Environment.PRODUCTION,
            
            # Advanced Analytics (staging and dev)
            "advanced_analytics": self.environment != Environment.PRODUCTION,
            "real_time_monitoring": self.environment != Environment.PRODUCTION,
            "performance_optimization": self.environment != Environment.PRODUCTION,
            
            # Security Features (always enabled)
            "security_headers": True,
            "input_validation": True,
            "threat_detection": True,
            "audit_logging": True,
            
            # Compliance Features (staging and dev)
            "soc2_compliance": self.environment != Environment.PRODUCTION,
            "iso27001_compliance": self.environment != Environment.PRODUCTION,
            "hipaa_compliance": self.environment != Environment.PRODUCTION,
            "gdpr_compliance": self.environment != Environment.PRODUCTION,
            
            # Performance Features (staging and dev)
            "auto_scaling": self.environment != Environment.PRODUCTION,
            "load_balancing": self.environment != Environment.PRODUCTION,
            "caching": True,  # Always enabled for performance
            
            # Development Features (dev only)
            "debug_endpoints": self.environment == Environment.DEVELOPMENT,
            "test_data_generation": self.environment == Environment.DEVELOPMENT,
            "development_tools": self.environment == Environment.DEVELOPMENT,
        }
    
    def is_enabled(self, feature: str) -> bool:
        """Check if a feature is enabled for the current environment"""
        enabled = self.flags.get(feature, False)
        logger.debug(f"Feature '{feature}' enabled: {enabled} (environment: {self.environment.value})")
        return enabled
    
    def get_environment_config(self) -> Dict[str, Any]:
        """Get complete environment configuration for API endpoint"""
        enabled_features = [k for k, v in self.flags.items() if v]
        disabled_features = [k for k, v in self.flags.items() if not v]
        
        return {
            "environment": self.environment.value,
            "enabled_features": enabled_features,
            "disabled_features": disabled_features,
            "feature_count": {
                "enabled": len(enabled_features),
                "disabled": len(disabled_features),
                "total": len(self.flags)
            }
        }
    
    def get_feature_status(self, feature: str) -> Dict[str, Any]:
        """Get detailed status of a specific feature"""
        enabled = self.is_enabled(feature)
        return {
            "feature": feature,
            "enabled": enabled,
            "environment": self.environment.value,
            "available_in_production": self.flags.get(feature, False) if self.environment == Environment.PRODUCTION else None
        }
    
    def list_features_by_category(self) -> Dict[str, list]:
        """List features grouped by category"""
        categories = {
            "fedramp": [k for k in self.flags.keys() if k.startswith("fedramp")],
            "ai_ml": [k for k in self.flags.keys() if k.startswith("ai_") or k.startswith("model")],
            "security": [k for k in self.flags.keys() if k.startswith("security") or k.startswith("threat") or k.startswith("audit")],
            "compliance": [k for k in self.flags.keys() if k.endswith("_compliance")],
            "performance": [k for k in self.flags.keys() if k in ["auto_scaling", "load_balancing", "caching", "performance_optimization"]],
            "development": [k for k in self.flags.keys() if k in ["debug_endpoints", "test_data_generation", "development_tools"]],
            "api": [k for k in self.flags.keys() if k.startswith("api_")],
            "scanner": [k for k in self.flags.keys() if k.startswith("scanner") or k.startswith("multi_") or k.startswith("custom_")],
            "analytics": [k for k in self.flags.keys() if k in ["advanced_analytics", "real_time_monitoring"]]
        }
        
        return {
            category: {
                "features": features,
                "enabled_count": len([f for f in features if self.is_enabled(f)]),
                "total_count": len(features)
            }
            for category, features in categories.items()
        }

# Global instance
feature_flags = FeatureFlags() 