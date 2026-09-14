"""
Advanced Security Module for VulnRisk
Implements enterprise-grade security features with minimal dependencies
"""

import re
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# FastAPI imports
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityEventType(Enum):
    THREAT_DETECTED = "threat_detected"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    AUTHENTICATION_FAILURE = "authentication_failure"
    INPUT_VALIDATION_FAILURE = "input_validation_failure"
    SECURITY_HEADER_MISSING = "security_header_missing"

@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: SecurityEventType
    threat_level: ThreatLevel
    source_ip: str
    user_agent: str
    endpoint: str
    details: Dict[str, Any]
    request_id: Optional[str] = None

@dataclass
class ThreatPattern:
    pattern: str
    threat_level: ThreatLevel
    description: str
    category: str

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add comprehensive security headers"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Essential security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Content Security Policy - Allow Swagger UI CDN resources for development
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self' http://localhost:3000 http://localhost:8000; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp_policy
        
        # HSTS (only for HTTPS)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response

class InputValidationService:
    """Advanced input validation and sanitization"""
    
    def __init__(self):
        # SQL Injection patterns
        self.sql_patterns = [
            r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
            r"(\b(or|and)\b\s+\d+\s*=\s*\d+)",
            r"(--|#|/\*|\*/)",
            r"(\bxp_|sp_|sysobjects|syscolumns)",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
        ]
        
        # Path traversal patterns
        self.path_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"~",
            r"/etc/",
            r"/var/",
            r"c:\\",
        ]
        
        # Command injection patterns
        self.command_patterns = [
            r"[;&|`$()]",
            r"\b(cat|ls|pwd|whoami|id|uname|ps|netstat)\b",
            r"\b(rm|del|mkdir|touch|chmod|chown)\b",
        ]
        
        # Compile patterns for efficiency
        self.compiled_patterns = {
            'sql': [re.compile(p, re.IGNORECASE) for p in self.sql_patterns],
            'xss': [re.compile(p, re.IGNORECASE) for p in self.xss_patterns],
            'path': [re.compile(p, re.IGNORECASE) for p in self.path_patterns],
            'command': [re.compile(p, re.IGNORECASE) for p in self.command_patterns],
        }
    
    def validate_input(self, input_data: str, input_type: str = "general") -> Dict[str, Any]:
        """Validate and sanitize input data"""
        result = {
            "is_valid": True,
            "threats": [],
            "sanitized": input_data,
            "validation_errors": []
        }
        
        if not input_data:
            return result
        
        # Check for various attack patterns
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(input_data):
                    result["is_valid"] = False
                    result["threats"].append({
                        "category": category,
                        "pattern": pattern.pattern,
                        "severity": "high"
                    })
        
        # Type-specific validation
        if input_type == "email":
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, input_data):
                result["is_valid"] = False
                result["validation_errors"].append("Invalid email format")
        
        elif input_type == "url":
            url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
            if not re.match(url_pattern, input_data):
                result["is_valid"] = False
                result["validation_errors"].append("Invalid URL format")
        
        elif input_type == "cve_id":
            cve_pattern = r"^CVE-\d{4}-\d{4,7}$"
            if not re.match(cve_pattern, input_data):
                result["is_valid"] = False
                result["validation_errors"].append("Invalid CVE ID format")
        
        # Basic sanitization
        if result["is_valid"]:
            result["sanitized"] = self._sanitize_input(input_data)
        
        return result
    
    def _sanitize_input(self, input_data: str) -> str:
        """Basic input sanitization"""
        # Remove null bytes
        sanitized = input_data.replace('\x00', '')
        
        # Remove control characters except newlines and tabs
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\n\t')
        
        # Trim whitespace
        sanitized = sanitized.strip()
        
        return sanitized

class ThreatDetectionService:
    """Real-time threat detection and analysis"""
    
    def __init__(self):
        self.rate_limits = defaultdict(lambda: {"count": 0, "window_start": time.time()})
        self.suspicious_ips = set()
        self.threat_patterns = self._initialize_threat_patterns()
        self.anomaly_thresholds = {
            "requests_per_minute": 100,
            "failed_auth_per_minute": 5,
            "suspicious_patterns_per_minute": 10,
        }
    
    def _initialize_threat_patterns(self) -> List[ThreatPattern]:
        """Initialize threat detection patterns"""
        return [
            ThreatPattern(
                pattern=r"admin['\"\s]*(or|and)['\"\s]*1['\"\s]*=['\"\s]*1",
                threat_level=ThreatLevel.HIGH,
                description="SQL injection attempt",
                category="sql_injection"
            ),
            ThreatPattern(
                pattern=r"<script[^>]*>.*?</script>",
                threat_level=ThreatLevel.HIGH,
                description="XSS attempt",
                category="xss"
            ),
            ThreatPattern(
                pattern=r"\.\./\.\./",
                threat_level=ThreatLevel.MEDIUM,
                description="Path traversal attempt",
                category="path_traversal"
            ),
            ThreatPattern(
                pattern=r";\s*(cat|ls|pwd|whoami)",
                threat_level=ThreatLevel.HIGH,
                description="Command injection attempt",
                category="command_injection"
            ),
            ThreatPattern(
                pattern=r"union\s+select",
                threat_level=ThreatLevel.CRITICAL,
                description="SQL union injection",
                category="sql_injection"
            ),
        ]
    
    def analyze_request(self, request: Request, client_ip: str) -> Dict[str, Any]:
        """Analyze request for threats"""
        analysis = {
            "threats_detected": [],
            "risk_score": 0,
            "recommendations": [],
            "is_suspicious": False
        }
        
        # Check rate limiting
        rate_limit_result = self._check_rate_limit(client_ip)
        if not rate_limit_result["allowed"]:
            analysis["threats_detected"].append({
                "type": "rate_limit_exceeded",
                "severity": "medium",
                "details": f"Rate limit exceeded: {rate_limit_result['current_count']} requests"
            })
            analysis["risk_score"] += 30
        
        # Check for suspicious patterns in URL and headers
        url_threats = self._analyze_url(request.url.path, request.url.query)
        analysis["threats_detected"].extend(url_threats)
        analysis["risk_score"] += len(url_threats) * 10
        
        # Check user agent
        user_agent = request.headers.get("user-agent", "")
        if self._is_suspicious_user_agent(user_agent):
            analysis["threats_detected"].append({
                "type": "suspicious_user_agent",
                "severity": "low",
                "details": f"Suspicious user agent: {user_agent}"
            })
            analysis["risk_score"] += 5
        
        # Determine if request is suspicious
        analysis["is_suspicious"] = analysis["risk_score"] > 20
        
        # Generate recommendations
        if analysis["is_suspicious"]:
            analysis["recommendations"].append("Consider blocking this IP address")
            analysis["recommendations"].append("Enable additional monitoring")
        
        return analysis
    
    def _check_rate_limit(self, client_ip: str) -> Dict[str, Any]:
        """Check if client has exceeded rate limits"""
        current_time = time.time()
        client_data = self.rate_limits[client_ip]
        
        # Reset window if needed
        if current_time - client_data["window_start"] > 60:  # 1 minute window
            client_data["count"] = 0
            client_data["window_start"] = current_time
        
        client_data["count"] += 1
        
        return {
            "allowed": client_data["count"] <= self.anomaly_thresholds["requests_per_minute"],
            "current_count": client_data["count"],
            "limit": self.anomaly_thresholds["requests_per_minute"]
        }
    
    def _analyze_url(self, path: str, query: str) -> List[Dict[str, Any]]:
        """Analyze URL for suspicious patterns"""
        threats = []
        full_url = f"{path}?{query}" if query else path
        
        for pattern in self.threat_patterns:
            if re.search(pattern.pattern, full_url, re.IGNORECASE):
                threats.append({
                    "type": pattern.category,
                    "severity": pattern.threat_level.value,
                    "details": pattern.description,
                    "pattern_matched": pattern.pattern
                })
        
        return threats
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious"""
        suspicious_patterns = [
            r"bot|crawler|spider",
            r"sqlmap",
            r"nikto",
            r"nmap",
            r"curl",
            r"wget",
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        
        return False

class SecurityAuditService:
    """Comprehensive security audit logging"""
    
    def __init__(self):
        self.events: deque = deque(maxlen=10000)  # Keep last 10k events
        self.alert_thresholds = {
            ThreatLevel.LOW: 100,
            ThreatLevel.MEDIUM: 50,
            ThreatLevel.HIGH: 20,
            ThreatLevel.CRITICAL: 5,
        }
    
    def log_event(self, event: SecurityEvent):
        """Log a security event"""
        self.events.append(event)
        logger.warning(f"Security Event: {event.event_type.value} - {event.threat_level.value} - {event.source_ip}")
        
        # Check if we need to generate an alert
        if self._should_generate_alert(event):
            self._generate_alert(event)
    
    def _should_generate_alert(self, event: SecurityEvent) -> bool:
        """Determine if an alert should be generated"""
        # Count recent events of same level
        recent_events = [
            e for e in self.events 
            if e.threat_level == event.threat_level 
            and (datetime.now() - e.timestamp).seconds < 3600  # Last hour
        ]
        
        return len(recent_events) >= self.alert_thresholds[event.threat_level]
    
    def _generate_alert(self, event: SecurityEvent):
        """Generate security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "security_alert",
            "threat_level": event.threat_level.value,
            "event_type": event.event_type.value,
            "source_ip": event.source_ip,
            "details": event.details,
            "message": f"Security alert: {event.threat_level.value} threat detected from {event.source_ip}"
        }
        
        logger.critical(f"SECURITY ALERT: {alert['message']}")
        # In production, this would send to monitoring system, email, etc.
    
    def get_events(self, 
                   threat_level: Optional[ThreatLevel] = None,
                   event_type: Optional[SecurityEventType] = None,
                   hours: int = 24) -> List[Dict[str, Any]]:
        """Get security events with optional filtering"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        filtered_events = [
            e for e in self.events
            if e.timestamp >= cutoff_time
            and (threat_level is None or e.threat_level == threat_level)
            and (event_type is None or e.event_type == event_type)
        ]
        
        return [asdict(event) for event in filtered_events]
    
    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get security summary statistics"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_events = [e for e in self.events if e.timestamp >= cutoff_time]
        
        summary = {
            "total_events": len(recent_events),
            "events_by_level": defaultdict(int),
            "events_by_type": defaultdict(int),
            "top_source_ips": defaultdict(int),
            "time_period_hours": hours
        }
        
        for event in recent_events:
            summary["events_by_level"][event.threat_level.value] += 1
            summary["events_by_type"][event.event_type.value] += 1
            summary["top_source_ips"][event.source_ip] += 1
        
        # Convert defaultdict to regular dict
        summary["events_by_level"] = dict(summary["events_by_level"])
        summary["events_by_type"] = dict(summary["events_by_type"])
        summary["top_source_ips"] = dict(summary["top_source_ips"])
        
        return summary

# Global instances
input_validator = InputValidationService()
threat_detector = ThreatDetectionService()
security_auditor = SecurityAuditService() 