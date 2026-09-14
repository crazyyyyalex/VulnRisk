"""
Feature Guards for VulnRisk

This module provides decorators and utilities to protect endpoints based on feature flags.
"""

from functools import wraps
from fastapi import HTTPException, Depends, Request
from typing import Callable, Any
import logging

from ..config.feature_flags import feature_flags

logger = logging.getLogger(__name__)

def require_feature(feature_name: str):
    """
    Decorator to require a specific feature to be enabled for an endpoint.
    
    Args:
        feature_name: Name of the feature that must be enabled
        
    Raises:
        HTTPException: 404 if feature is not available in current environment
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not feature_flags.is_enabled(feature_name):
                logger.warning(f"Feature '{feature_name}' requested but not enabled in {feature_flags.environment.value}")
                raise HTTPException(
                    status_code=404,
                    detail={
                        "error": "Feature not available",
                        "feature": feature_name,
                        "environment": feature_flags.environment.value,
                        "message": f"Feature '{feature_name}' is not available in the current environment"
                    }
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def get_feature_dependency(feature_name: str):
    """
    FastAPI dependency injection for feature availability.
    
    Args:
        feature_name: Name of the feature to check
        
    Returns:
        FastAPI dependency that raises HTTPException if feature is disabled
    """
    def check_feature():
        if not feature_flags.is_enabled(feature_name):
            logger.warning(f"Feature '{feature_name}' dependency check failed in {feature_flags.environment.value}")
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "Feature not available",
                    "feature": feature_name,
                    "environment": feature_flags.environment.value,
                    "message": f"Feature '{feature_name}' is not available in the current environment"
                }
            )
        return True
    return Depends(check_feature)

def optional_feature(feature_name: str, default_value: Any = None):
    """
    Decorator for optional features that return a default value if disabled.
    
    Args:
        feature_name: Name of the feature to check
        default_value: Value to return if feature is disabled
        
    Returns:
        Decorated function that returns default_value if feature is disabled
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not feature_flags.is_enabled(feature_name):
                logger.info(f"Feature '{feature_name}' disabled, returning default value")
                return default_value
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def feature_guard_middleware():
    """
    Middleware to log feature usage and provide feature information in headers.
    """
    async def middleware(request: Request, call_next):
        # Add feature flag information to response headers
        response = await call_next(request)
        
        # Add feature flag headers for debugging
        response.headers["X-Feature-Environment"] = feature_flags.environment.value
        response.headers["X-Features-Enabled"] = str(len([k for k, v in feature_flags.flags.items() if v]))
        response.headers["X-Features-Total"] = str(len(feature_flags.flags))
        
        return response
    
    return middleware

class FeatureGuard:
    """
    Context manager for feature availability checks.
    """
    def __init__(self, feature_name: str, raise_on_disabled: bool = True):
        self.feature_name = feature_name
        self.raise_on_disabled = raise_on_disabled
        self.enabled = feature_flags.is_enabled(feature_name)
    
    def __enter__(self):
        if not self.enabled and self.raise_on_disabled:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "Feature not available",
                    "feature": self.feature_name,
                    "environment": feature_flags.environment.value,
                    "message": f"Feature '{self.feature_name}' is not available in the current environment"
                }
            )
        return self.enabled
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

def check_feature_availability(feature_name: str) -> dict:
    """
    Check feature availability and return detailed status.
    
    Args:
        feature_name: Name of the feature to check
        
    Returns:
        Dictionary with feature status information
    """
    return feature_flags.get_feature_status(feature_name)

def get_available_features() -> dict:
    """
    Get all available features for the current environment.
    
    Returns:
        Dictionary with feature configuration
    """
    return feature_flags.get_environment_config()

def is_feature_enabled(feature_name: str) -> bool:
    """
    Simple check if a feature is enabled.
    
    Args:
        feature_name: Name of the feature to check
        
    Returns:
        True if feature is enabled, False otherwise
    """
    return feature_flags.is_enabled(feature_name)

# Convenience functions for common feature checks
def require_fedramp():
    """Require FedRAMP compliance features to be enabled."""
    return require_feature("fedramp_compliance")

def require_ai_ml():
    """Require AI/ML features to be enabled."""
    return require_feature("ai_risk_prediction")

def require_scanner_integration():
    """Require scanner integration features to be enabled."""
    return require_feature("scanner_integrations")

def require_advanced_analytics():
    """Require advanced analytics features to be enabled."""
    return require_feature("advanced_analytics")

def require_development():
    """Require development features to be enabled."""
    return require_feature("debug_endpoints")

# Dependency injection helpers
def get_fedramp_dependency():
    """FastAPI dependency for FedRAMP features."""
    return get_feature_dependency("fedramp_compliance")

def get_ai_ml_dependency():
    """FastAPI dependency for AI/ML features."""
    return get_feature_dependency("ai_risk_prediction")

def get_scanner_dependency():
    """FastAPI dependency for scanner features."""
    return get_feature_dependency("scanner_integrations")

def get_analytics_dependency():
    """FastAPI dependency for analytics features."""
    return get_feature_dependency("advanced_analytics") 