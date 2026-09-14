import os
import secrets
import base64
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

from ..models.api_keys import (
    CustomerAPIKey, APIKeyCreateRequest, APIKeyUpdateRequest, 
    APIKeyResponse, APIKeyUsageStats, APIKeyAuditLog, APIKeyType, APIKeyStatus
)
from ..auth.auth0_jwt import get_current_user

logger = logging.getLogger(__name__)

class APIKeyManager:
    """Secure API key management service for customer-specific keys"""
    
    def __init__(self):
        self._encryption_key = self._get_or_create_encryption_key()
        self._fernet = Fernet(self._encryption_key)
        self._customer_keys: Dict[str, List[CustomerAPIKey]] = {}  # In-memory storage for demo
        self._audit_logs: List[APIKeyAuditLog] = []
        self._usage_stats: Dict[str, Dict[str, Any]] = {}
        
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for API key storage"""
        key_env = os.getenv("API_KEY_ENCRYPTION_KEY")
        if key_env:
            return base64.urlsafe_b64decode(key_env)
        
        # Generate new key if not exists
        key = Fernet.generate_key()
        logger.warning(f"Generated new encryption key. Set API_KEY_ENCRYPTION_KEY={base64.urlsafe_b64encode(key).decode()}")
        return key
    
    def _encrypt_api_key(self, api_key: str) -> str:
        """Encrypt API key for secure storage"""
        try:
            encrypted = self._fernet.encrypt(api_key.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt API key: {e}")
            raise ValueError("Failed to encrypt API key")
    
    def _decrypt_api_key(self, encrypted_key: str) -> str:
        """Decrypt API key for use"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_key.encode())
            decrypted = self._fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt API key: {e}")
            raise ValueError("Failed to decrypt API key")
    
    def create_api_key(self, customer_id: str, request: APIKeyCreateRequest) -> APIKeyResponse:
        """Create a new API key for a customer"""
        try:
            # Encrypt the API key
            encrypted_key = self._encrypt_api_key(request.api_key_value)
            
            # Create the API key record
            api_key = CustomerAPIKey(
                customer_id=customer_id,
                key_type=request.key_type,
                key_name=request.key_name,
                encrypted_key=encrypted_key,
                expires_at=request.expires_at,
                rate_limit=request.rate_limit,
                metadata=request.metadata
            )
            
            # Store in memory (in production, this would be in a database)
            if customer_id not in self._customer_keys:
                self._customer_keys[customer_id] = []
            self._customer_keys[customer_id].append(api_key)
            
            # Log audit event
            self._log_audit_event(customer_id, api_key.id, "create", {
                "key_type": request.key_type,
                "key_name": request.key_name,
                "has_expiration": bool(request.expires_at)
            })
            
            # Initialize usage stats
            self._usage_stats[api_key.id] = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "last_used": None,
                "response_times": []
            }
            
            return self._to_response(api_key)
            
        except Exception as e:
            logger.error(f"Failed to create API key for customer {customer_id}: {e}")
            raise ValueError(f"Failed to create API key: {str(e)}")
    
    def get_customer_api_keys(self, customer_id: str) -> List[APIKeyResponse]:
        """Get all API keys for a customer"""
        if customer_id not in self._customer_keys:
            return []
        
        return [self._to_response(key) for key in self._customer_keys[customer_id]]
    
    def get_api_key(self, customer_id: str, key_id: str) -> Optional[APIKeyResponse]:
        """Get a specific API key for a customer"""
        if customer_id not in self._customer_keys:
            return None
        
        for key in self._customer_keys[customer_id]:
            if key.id == key_id:
                return self._to_response(key)
        
        return None
    
    def update_api_key(self, customer_id: str, key_id: str, request: APIKeyUpdateRequest) -> Optional[APIKeyResponse]:
        """Update an API key"""
        if customer_id not in self._customer_keys:
            return None
        
        for key in self._customer_keys[customer_id]:
            if key.id == key_id:
                # Update fields
                if request.key_name is not None:
                    key.key_name = request.key_name
                if request.status is not None:
                    key.status = request.status
                if request.expires_at is not None:
                    key.expires_at = request.expires_at
                if request.rate_limit is not None:
                    key.rate_limit = request.rate_limit
                if request.metadata is not None:
                    key.metadata.update(request.metadata)
                
                key.updated_at = datetime.utcnow()
                
                # Log audit event
                self._log_audit_event(customer_id, key_id, "update", {
                    "updated_fields": [k for k, v in request.dict(exclude_unset=True).items() if v is not None]
                })
                
                return self._to_response(key)
        
        return None
    
    def delete_api_key(self, customer_id: str, key_id: str) -> bool:
        """Delete an API key"""
        if customer_id not in self._customer_keys:
            return False
        
        for i, key in enumerate(self._customer_keys[customer_id]):
            if key.id == key_id:
                # Log audit event before deletion
                self._log_audit_event(customer_id, key_id, "delete", {
                    "key_type": key.key_type,
                    "key_name": key.key_name
                })
                
                # Remove from storage
                del self._customer_keys[customer_id][i]
                
                # Clean up usage stats
                if key_id in self._usage_stats:
                    del self._usage_stats[key_id]
                
                return True
        
        return False
    
    def rotate_api_key(self, customer_id: str, key_id: str, new_key_value: str, reason: Optional[str] = None) -> Optional[APIKeyResponse]:
        """Rotate an API key with a new value"""
        if customer_id not in self._customer_keys:
            return None
        
        for key in self._customer_keys[customer_id]:
            if key.id == key_id:
                # Encrypt new key
                encrypted_new_key = self._encrypt_api_key(new_key_value)
                
                # Update the key
                key.encrypted_key = encrypted_new_key
                key.updated_at = datetime.utcnow()
                
                # Log audit event
                self._log_audit_event(customer_id, key_id, "rotate", {
                    "reason": reason or "Security rotation"
                })
                
                return self._to_response(key)
        
        return None
    
    def get_api_key_value(self, customer_id: str, key_id: str, key_type: APIKeyType) -> Optional[str]:
        """Get the decrypted API key value for use in API calls"""
        if customer_id not in self._customer_keys:
            return None
        
        for key in self._customer_keys[customer_id]:
            if key.id == key_id and key.key_type == key_type and key.status == APIKeyStatus.ACTIVE:
                # Check expiration
                if key.expires_at and key.expires_at < datetime.utcnow():
                    key.status = APIKeyStatus.EXPIRED
                    return None
                
                # Update usage stats
                self._update_usage_stats(key_id, True)
                
                # Update last used
                key.last_used_at = datetime.utcnow()
                key.usage_count += 1
                
                return self._decrypt_api_key(key.encrypted_key)
        
        return None
    
    def get_customer_default_key(self, customer_id: str, key_type: APIKeyType) -> Optional[str]:
        """Get the default (first active) API key for a customer and key type"""
        if customer_id not in self._customer_keys:
            return None
        
        for key in self._customer_keys[customer_id]:
            if (key.key_type == key_type and 
                key.status == APIKeyStatus.ACTIVE and
                (not key.expires_at or key.expires_at > datetime.utcnow())):
                return self._decrypt_api_key(key.encrypted_key)
        
        return None
    
    def get_usage_stats(self, customer_id: str, key_id: str) -> Optional[APIKeyUsageStats]:
        """Get usage statistics for an API key"""
        if key_id not in self._usage_stats:
            return None
        
        key = self.get_api_key(customer_id, key_id)
        if not key:
            return None
        
        stats = self._usage_stats[key_id]
        total = stats["total_requests"]
        successful = stats["successful_requests"]
        failed = stats["failed_requests"]
        
        # Calculate average response time
        avg_response_time = None
        if stats["response_times"]:
            avg_response_time = sum(stats["response_times"]) / len(stats["response_times"])
        
        # Calculate error rate
        error_rate = failed / total if total > 0 else 0.0
        
        return APIKeyUsageStats(
            key_id=key_id,
            key_name=key.key_name,
            key_type=key.key_type,
            total_requests=total,
            successful_requests=successful,
            failed_requests=failed,
            last_used=stats["last_used"],
            average_response_time=avg_response_time,
            error_rate=error_rate
        )
    
    def _update_usage_stats(self, key_id: str, success: bool, response_time: Optional[float] = None):
        """Update usage statistics for an API key"""
        if key_id not in self._usage_stats:
            self._usage_stats[key_id] = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "last_used": None,
                "response_times": []
            }
        
        stats = self._usage_stats[key_id]
        stats["total_requests"] += 1
        stats["last_used"] = datetime.utcnow()
        
        if success:
            stats["successful_requests"] += 1
        else:
            stats["failed_requests"] += 1
        
        if response_time is not None:
            stats["response_times"].append(response_time)
            # Keep only last 100 response times
            if len(stats["response_times"]) > 100:
                stats["response_times"] = stats["response_times"][-100:]
    
    def _log_audit_event(self, customer_id: str, key_id: str, action: str, details: Dict[str, Any]):
        """Log an audit event for API key operations"""
        audit_log = APIKeyAuditLog(
            customer_id=customer_id,
            key_id=key_id,
            action=action,
            details=details
        )
        self._audit_logs.append(audit_log)
        logger.info(f"API Key Audit: {action} for key {key_id} by customer {customer_id}")
    
    def _to_response(self, api_key: CustomerAPIKey) -> APIKeyResponse:
        """Convert internal API key to response model (without sensitive data)"""
        return APIKeyResponse(
            id=api_key.id,
            customer_id=api_key.customer_id,
            key_type=api_key.key_type,
            key_name=api_key.key_name,
            status=api_key.status,
            created_at=api_key.created_at,
            updated_at=api_key.updated_at,
            expires_at=api_key.expires_at,
            last_used_at=api_key.last_used_at,
            usage_count=api_key.usage_count,
            rate_limit=api_key.rate_limit,
            metadata=api_key.metadata
        )
    
    def get_audit_logs(self, customer_id: str, key_id: Optional[str] = None) -> List[APIKeyAuditLog]:
        """Get audit logs for a customer"""
        logs = [log for log in self._audit_logs if log.customer_id == customer_id]
        if key_id:
            logs = [log for log in logs if log.key_id == key_id]
        return sorted(logs, key=lambda x: x.timestamp, reverse=True)

# Global instance
api_key_manager = APIKeyManager() 