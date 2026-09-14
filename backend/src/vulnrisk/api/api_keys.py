from fastapi import APIRouter, HTTPException, Depends, Request
from typing import List, Optional
from datetime import datetime

from ..models.api_keys import (
    APIKeyCreateRequest, APIKeyUpdateRequest, APIKeyResponse, 
    APIKeyUsageStats, APIKeyRotationRequest, APIKeyAuditLog, APIKeyType
)
from ..services.api_key_manager import api_key_manager
from ..auth.auth0_jwt import get_current_user

router = APIRouter(prefix="/api/v1/api-keys", tags=["API Key Management"])

@router.post("/", response_model=APIKeyResponse)
async def create_api_key(
    request: APIKeyCreateRequest,
    user: dict = Depends(get_current_user),
    req: Request = None
):
    """Create a new API key for the authenticated customer"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        # Add request metadata
        request.metadata.update({
            "created_via": "api",
            "ip_address": req.client.host if req else None,
            "user_agent": req.headers.get("user-agent") if req else None
        })
        
        api_key = api_key_manager.create_api_key(customer_id, request)
        return api_key
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create API key: {str(e)}")

@router.get("/", response_model=List[APIKeyResponse])
async def list_api_keys(user: dict = Depends(get_current_user)):
    """Get all API keys for the authenticated customer"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        api_keys = api_key_manager.get_customer_api_keys(customer_id)
        return api_keys
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve API keys: {str(e)}")

@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(key_id: str, user: dict = Depends(get_current_user)):
    """Get a specific API key for the authenticated customer"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        api_key = api_key_manager.get_api_key(customer_id, key_id)
        if not api_key:
            raise HTTPException(status_code=404, detail="API key not found")
        
        return api_key
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve API key: {str(e)}")

@router.put("/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    key_id: str,
    request: APIKeyUpdateRequest,
    user: dict = Depends(get_current_user)
):
    """Update an API key for the authenticated customer"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        api_key = api_key_manager.update_api_key(customer_id, key_id, request)
        if not api_key:
            raise HTTPException(status_code=404, detail="API key not found")
        
        return api_key
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update API key: {str(e)}")

@router.delete("/{key_id}")
async def delete_api_key(key_id: str, user: dict = Depends(get_current_user)):
    """Delete an API key for the authenticated customer"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        success = api_key_manager.delete_api_key(customer_id, key_id)
        if not success:
            raise HTTPException(status_code=404, detail="API key not found")
        
        return {"message": "API key deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete API key: {str(e)}")

@router.post("/{key_id}/rotate", response_model=APIKeyResponse)
async def rotate_api_key(
    key_id: str,
    request: APIKeyRotationRequest,
    user: dict = Depends(get_current_user)
):
    """Rotate an API key with a new value"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        api_key = api_key_manager.rotate_api_key(
            customer_id, key_id, request.new_api_key_value, request.rotation_reason
        )
        if not api_key:
            raise HTTPException(status_code=404, detail="API key not found")
        
        return api_key
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rotate API key: {str(e)}")

@router.get("/{key_id}/stats", response_model=APIKeyUsageStats)
async def get_api_key_stats(key_id: str, user: dict = Depends(get_current_user)):
    """Get usage statistics for an API key"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        stats = api_key_manager.get_usage_stats(customer_id, key_id)
        if not stats:
            raise HTTPException(status_code=404, detail="API key not found")
        
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve usage stats: {str(e)}")

@router.get("/{key_id}/audit-logs", response_model=List[APIKeyAuditLog])
async def get_api_key_audit_logs(
    key_id: str,
    user: dict = Depends(get_current_user),
    limit: Optional[int] = 50
):
    """Get audit logs for an API key"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        logs = api_key_manager.get_audit_logs(customer_id, key_id)
        if limit:
            logs = logs[:limit]
        
        return logs
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve audit logs: {str(e)}")

@router.get("/audit-logs/all", response_model=List[APIKeyAuditLog])
async def get_all_audit_logs(
    user: dict = Depends(get_current_user),
    limit: Optional[int] = 100
):
    """Get all audit logs for the authenticated customer"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        logs = api_key_manager.get_audit_logs(customer_id)
        if limit:
            logs = logs[:limit]
        
        return logs
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve audit logs: {str(e)}")

@router.get("/types/supported", response_model=List[str])
async def get_supported_api_key_types():
    """Get list of supported API key types"""
    return [key_type.value for key_type in APIKeyType]

@router.post("/validate")
async def validate_api_key(
    key_type: APIKeyType,
    api_key_value: str,
    user: dict = Depends(get_current_user)
):
    """Validate an API key by testing it against the actual service"""
    try:
        customer_id = user.get("sub")
        if not customer_id:
            raise HTTPException(status_code=401, detail="Invalid user authentication")
        
        # Test the API key based on type
        is_valid = False
        error_message = None
        
        if key_type == APIKeyType.NVD:
            # Test NVD API key
            from ..data_sources.nvd import NVDClient
            nvd_client = NVDClient(api_key=api_key_value)
            try:
                # Test with a known CVE
                result = await nvd_client.get_cvss_score("CVE-2021-44228")
                is_valid = result is not None
                if not is_valid:
                    error_message = "API key is invalid or has insufficient permissions"
            except Exception as e:
                is_valid = False
                error_message = f"NVD API test failed: {str(e)}"
        
        elif key_type == APIKeyType.EPSS:
            # EPSS doesn't require API keys, so this is always valid
            is_valid = True
            error_message = "EPSS API doesn't require authentication"
        
        elif key_type == APIKeyType.CISA_KEV:
            # Test CISA KEV API (if it requires authentication)
            is_valid = True
            error_message = "CISA KEV API validation not implemented"
        
        else:
            is_valid = False
            error_message = f"Validation not supported for key type: {key_type}"
        
        return {
            "is_valid": is_valid,
            "key_type": key_type,
            "error_message": error_message
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to validate API key: {str(e)}") 