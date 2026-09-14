from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import secrets
import string

class APIKeyType(str, Enum):
    """Types of API keys that customers can manage"""
    NVD = "nvd"
    EPSS = "epss"
    CISA_KEV = "cisa_kev"
    CUSTOM = "custom"

class APIKeyStatus(str, Enum):
    """Status of API keys"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    REVOKED = "revoked"

class CustomerAPIKey(BaseModel):
    """Customer API key model for secure storage"""
    id: str = Field(default_factory=lambda: secrets.token_urlsafe(16))
    customer_id: str = Field(..., description="Auth0 user ID of the customer")
    key_type: APIKeyType = Field(..., description="Type of API key")
    key_name: str = Field(..., min_length=1, max_length=100, description="Human-readable name for the key")
    encrypted_key: str = Field(..., description="Encrypted API key value")
    status: APIKeyStatus = Field(default=APIKeyStatus.ACTIVE)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = Field(None, description="Optional expiration date")
    last_used_at: Optional[datetime] = Field(None, description="Last time the key was used")
    usage_count: int = Field(default=0, description="Number of times the key has been used")
    rate_limit: Optional[int] = Field(None, description="Rate limit for this key (requests per hour)")
    metadata: dict = Field(default_factory=dict, description="Additional metadata")

    @validator('key_name')
    def validate_key_name(cls, v):
        """Validate key name format"""
        if not v.strip():
            raise ValueError('Key name cannot be empty')
        return v.strip()

class APIKeyCreateRequest(BaseModel):
    """Request model for creating new API keys"""
    key_type: APIKeyType
    key_name: str = Field(..., min_length=1, max_length=100)
    api_key_value: str = Field(..., min_length=1, description="The actual API key value")
    expires_at: Optional[datetime] = None
    rate_limit: Optional[int] = None
    metadata: dict = Field(default_factory=dict)

    @validator('api_key_value')
    def validate_api_key(cls, v):
        """Basic validation for API key format"""
        if not v.strip():
            raise ValueError('API key cannot be empty')
        return v.strip()

class APIKeyUpdateRequest(BaseModel):
    """Request model for updating API keys"""
    key_name: Optional[str] = Field(None, min_length=1, max_length=100)
    status: Optional[APIKeyStatus] = None
    expires_at: Optional[datetime] = None
    rate_limit: Optional[int] = None
    metadata: Optional[dict] = None

class APIKeyResponse(BaseModel):
    """Response model for API key data (without sensitive information)"""
    id: str
    customer_id: str
    key_type: APIKeyType
    key_name: str
    status: APIKeyStatus
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    usage_count: int
    rate_limit: Optional[int]
    metadata: dict

class APIKeyUsageStats(BaseModel):
    """API key usage statistics"""
    key_id: str
    key_name: str
    key_type: APIKeyType
    total_requests: int
    successful_requests: int
    failed_requests: int
    last_used: Optional[datetime]
    average_response_time: Optional[float]
    error_rate: float = Field(0.0, ge=0.0, le=1.0)

class APIKeyRotationRequest(BaseModel):
    """Request model for rotating API keys"""
    new_api_key_value: str = Field(..., min_length=1)
    rotation_reason: Optional[str] = Field(None, max_length=500)

class APIKeyAuditLog(BaseModel):
    """Audit log entry for API key operations"""
    id: str = Field(default_factory=lambda: secrets.token_urlsafe(16))
    customer_id: str
    key_id: str
    action: str = Field(..., description="Action performed (create, update, delete, rotate, etc.)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: dict = Field(default_factory=dict) 