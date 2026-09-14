import os
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from typing import Dict, Any, Optional
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

ALGORITHMS = ["RS256"]

def get_auth0_config():
    """Get Auth0 configuration from environment variables."""
    domain = os.getenv("AUTH0_DOMAIN")
    audience = os.getenv("AUTH0_AUDIENCE")
    
    if not domain or not audience:
        raise ValueError("AUTH0_DOMAIN and AUTH0_AUDIENCE must be set")
    
    return domain, audience

def verify_jwt_token(token: str) -> Dict[str, Any]:
    """Verify JWT token and return payload."""
    try:
        domain, audience = get_auth0_config()
        jwks_url = f"https://{domain}/.well-known/jwks.json"
        jwks = requests.get(jwks_url, timeout=10).json()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        if rsa_key:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=audience,
                issuer=f"https://{domain}/",
            )
            return payload
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to find appropriate key.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation error: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication error: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

class Auth0JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                if self.auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid authentication scheme.",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return None
            return verify_jwt_token(credentials.credentials)
        else:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authorization code.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

def get_current_user(token_payload: Dict[str, Any] = Depends(Auth0JWTBearer())) -> Dict[str, Any]:
    """
    Dependency to get the current user from the validated JWT payload.
    Returns the payload, which includes user info and roles/permissions.
    """
    return token_payload

def get_current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    """
    Optional dependency to get the current user from the validated JWT payload.
    Returns the payload if authenticated, None if not authenticated.
    """
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        token = auth_header.split(" ")[1]
        return verify_jwt_token(token)
    except Exception:
        return None