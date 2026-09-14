"""
Scanner Integration Service for VulnRisk
Supports multiple vulnerability scanners and security tools
"""

import asyncio
import subprocess
import json
import xml.etree.ElementTree as ET
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import os
from dataclasses import dataclass
from enum import Enum

class ScannerType(Enum):
    NUCLEI = "nuclei"
    NESSUS = "nessus"
    OPENVAS = "openvas"
    TRIVY = "trivy"
    ZAP = "zap"
    SONARQUBE = "sonarqube"

@dataclass
class ScanResult:
    scanner_type: ScannerType
    target: str
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime]
    status: str
    findings: List[Dict[str, Any]]
    summary: Dict[str, Any]

class ScannerIntegrationService:
    """Comprehensive scanner integration service"""
    
    def __init__(self):
        self.scanners = {
            ScannerType.NUCLEI: NucleiScanner(),
            ScannerType.NESSUS: NessusScanner(),
            ScannerType.OPENVAS: OpenVASScanner(),
            ScannerType.TRIVY: TrivyScanner(),
            ScannerType.ZAP: ZAPScanner(),
            ScannerType.SONARQUBE: SonarQubeScanner()
        }
    
    async def run_scan(self, scanner_type: ScannerType, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """Run a scan with the specified scanner"""
        scanner = self.scanners.get(scanner_type)
        if not scanner:
            raise ValueError(f"Unsupported scanner type: {scanner_type}")
        
        return await scanner.scan(target, options or {})
    
    async def run_multi_scanner_scan(self, targets: List[str], scanners: List[ScannerType], options: Dict[str, Any] = None) -> List[ScanResult]:
        """Run multiple scanners on multiple targets"""
        tasks = []
        for scanner_type in scanners:
            for target in targets:
                task = self.run_scan(scanner_type, target, options)
                tasks.append(task)
        
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_available_scanners(self) -> List[Dict[str, Any]]:
        """Get list of available scanners with their capabilities"""
        return [
            {
                "type": ScannerType.NUCLEI.value,
                "name": "Nuclei",
                "description": "Fast and comprehensive vulnerability scanner",
                "capabilities": ["web", "infrastructure", "cloud", "api"],
                "supported_formats": ["json", "csv"],
                "requires_auth": False
            },
            {
                "type": ScannerType.NESSUS.value,
                "name": "Nessus",
                "description": "Enterprise vulnerability scanner",
                "capabilities": ["network", "web", "compliance"],
                "supported_formats": ["nessus", "csv", "html"],
                "requires_auth": True
            },
            {
                "type": ScannerType.OPENVAS.value,
                "name": "OpenVAS",
                "description": "Open-source vulnerability scanner",
                "capabilities": ["network", "web", "compliance"],
                "supported_formats": ["xml", "csv"],
                "requires_auth": True
            },
            {
                "type": ScannerType.TRIVY.value,
                "name": "Trivy",
                "description": "Container and infrastructure security scanner",
                "capabilities": ["container", "infrastructure", "iac"],
                "supported_formats": ["json", "table"],
                "requires_auth": False
            },
            {
                "type": ScannerType.ZAP.value,
                "name": "OWASP ZAP",
                "description": "Web application security scanner",
                "capabilities": ["web", "api", "spider"],
                "supported_formats": ["json", "xml", "html"],
                "requires_auth": False
            },
            {
                "type": ScannerType.SONARQUBE.value,
                "name": "SonarQube",
                "description": "Code quality and security analysis",
                "capabilities": ["code", "security", "quality"],
                "supported_formats": ["json", "xml"],
                "requires_auth": True
            }
        ]

class BaseScanner:
    """Base class for all scanners"""
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """Base scan method to be implemented by each scanner"""
        raise NotImplementedError
    
    def parse_results(self, raw_results: str) -> List[Dict[str, Any]]:
        """Parse scanner-specific results into standardized format"""
        raise NotImplementedError
    
    def convert_to_vulnrisk_format(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert scanner findings to VulnRisk format"""
        vulnrisk_findings = []
        
        for finding in findings:
            vulnrisk_finding = {
                "cve_id": finding.get("cve_id", finding.get("id", "")),
                "title": finding.get("title", finding.get("name", "")),
                "description": finding.get("description", ""),
                "severity": finding.get("severity", "medium"),
                "cvss_score": finding.get("cvss_score", 0),
                "category": finding.get("category", "vulnerability"),
                "location": finding.get("location", ""),
                "evidence": finding.get("evidence", ""),
                "remediation": finding.get("remediation", ""),
                "references": finding.get("references", []),
                "scanner": finding.get("scanner", ""),
                "timestamp": finding.get("timestamp", datetime.now().isoformat())
            }
            vulnrisk_findings.append(vulnrisk_finding)
        
        return vulnrisk_findings

class NucleiScanner(BaseScanner):
    """Nuclei scanner integration"""
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = f"nuclei_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        # Build Nuclei command
        cmd = ["nuclei", "-u", target, "-j", "-silent"]
        
        # Add optional parameters
        if options.get("templates"):
            cmd.extend(["-t", options["templates"]])
        if options.get("severity"):
            cmd.extend(["-severity", options["severity"]])
        if options.get("rate_limit"):
            cmd.extend(["-rate-limit", str(options["rate_limit"])])
        
        try:
            # Run Nuclei scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Nuclei scan failed: {stderr.decode()}")
            
            # Parse results
            raw_results = stdout.decode()
            findings = self.parse_results(raw_results)
            
            end_time = datetime.now()
            
            return ScanResult(
                scanner_type=ScannerType.NUCLEI,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=end_time,
                status="completed",
                findings=findings,
                summary=self._generate_summary(findings)
            )
            
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.NUCLEI,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=datetime.now(),
                status="failed",
                findings=[],
                summary={"error": str(e)}
            )
    
    def parse_results(self, raw_results: str) -> List[Dict[str, Any]]:
        """Parse Nuclei JSON output"""
        findings = []
        
        for line in raw_results.strip().split('\n'):
            if not line:
                continue
            
            try:
                result = json.loads(line)
                finding = {
                    "cve_id": result.get("cve", []),
                    "title": result.get("info", {}).get("name", ""),
                    "description": result.get("info", {}).get("description", ""),
                    "severity": result.get("info", {}).get("severity", "medium"),
                    "cvss_score": result.get("info", {}).get("cvss-score", 0),
                    "category": "vulnerability",
                    "location": result.get("host", ""),
                    "evidence": result.get("matcher-status", ""),
                    "remediation": result.get("info", {}).get("remediation", ""),
                    "references": result.get("info", {}).get("reference", []),
                    "scanner": "nuclei",
                    "timestamp": datetime.now().isoformat()
                }
                findings.append(finding)
            except json.JSONDecodeError:
                continue
        
        return findings
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for Nuclei findings"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "scanner": "nuclei"
        }

class NessusScanner(BaseScanner):
    """Nessus scanner integration"""
    
    def __init__(self):
        self.api_url = os.getenv("NESSUS_URL", "")
        self.api_key = os.getenv("NESSUS_API_KEY", "")
        self.access_key = os.getenv("NESSUS_ACCESS_KEY", "")
        self.secret_key = os.getenv("NESSUS_SECRET_KEY", "")
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = f"nessus_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        try:
            # Create scan
            scan_id_nessus = await self._create_scan(target, options)
            
            # Launch scan
            await self._launch_scan(scan_id_nessus)
            
            # Wait for completion and get results
            findings = await self._get_scan_results(scan_id_nessus)
            
            end_time = datetime.now()
            
            return ScanResult(
                scanner_type=ScannerType.NESSUS,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=end_time,
                status="completed",
                findings=findings,
                summary=self._generate_summary(findings)
            )
            
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.NESSUS,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=datetime.now(),
                status="failed",
                findings=[],
                summary={"error": str(e)}
            )
    
    async def _create_scan(self, target: str, options: Dict[str, Any]) -> str:
        """Create a new Nessus scan"""
        headers = {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
            "Content-Type": "application/json"
        }
        
        scan_config = {
            "uuid": options.get("policy_uuid", "basic"),
            "settings": {
                "name": f"VulnRisk Scan - {target}",
                "description": "Automated scan from VulnRisk",
                "targets": target,
                "enabled": True
            }
        }
        
        response = requests.post(
            f"{self.api_url}/scans",
            headers=headers,
            json=scan_config
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to create Nessus scan: {response.text}")
        
        return response.json()["scan"]["id"]
    
    async def _launch_scan(self, scan_id: str):
        """Launch a Nessus scan"""
        headers = {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}"
        }
        
        response = requests.post(
            f"{self.api_url}/scans/{scan_id}/launch",
            headers=headers
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to launch Nessus scan: {response.text}")
    
    async def _get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get Nessus scan results"""
        headers = {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}"
        }
        
        response = requests.get(
            f"{self.api_url}/scans/{scan_id}",
            headers=headers
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get Nessus scan results: {response.text}")
        
        scan_data = response.json()
        return self.parse_results(scan_data)
    
    def parse_results(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Nessus scan results"""
        findings = []
        
        for vulnerability in scan_data.get("vulnerabilities", []):
            finding = {
                "cve_id": vulnerability.get("cve", []),
                "title": vulnerability.get("plugin_name", ""),
                "description": vulnerability.get("description", ""),
                "severity": self._convert_severity(vulnerability.get("risk_factor", "medium")),
                "cvss_score": vulnerability.get("cvss_base_score", 0),
                "category": "vulnerability",
                "location": vulnerability.get("host", ""),
                "evidence": vulnerability.get("plugin_output", ""),
                "remediation": vulnerability.get("solution", ""),
                "references": vulnerability.get("see_also", []),
                "scanner": "nessus",
                "timestamp": datetime.now().isoformat()
            }
            findings.append(finding)
        
        return findings
    
    def _convert_severity(self, nessus_severity: str) -> str:
        """Convert Nessus severity to standard format"""
        severity_map = {
            "Critical": "critical",
            "High": "high", 
            "Medium": "medium",
            "Low": "low",
            "Info": "info"
        }
        return severity_map.get(nessus_severity, "medium")
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for Nessus findings"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "scanner": "nessus"
        }

class OpenVASScanner(BaseScanner):
    """OpenVAS scanner integration"""
    
    def __init__(self):
        self.api_url = os.getenv("OPENVAS_URL", "")
        self.username = os.getenv("OPENVAS_USERNAME", "")
        self.password = os.getenv("OPENVAS_PASSWORD", "")
        self.token = None
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = f"openvas_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        try:
            # Authenticate
            await self._authenticate()
            
            # Create scan
            scan_id_openvas = await self._create_scan(target, options)
            
            # Start scan
            await self._start_scan(scan_id_openvas)
            
            # Wait for completion and get results
            findings = await self._get_scan_results(scan_id_openvas)
            
            end_time = datetime.now()
            
            return ScanResult(
                scanner_type=ScannerType.OPENVAS,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=end_time,
                status="completed",
                findings=findings,
                summary=self._generate_summary(findings)
            )
            
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.OPENVAS,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=datetime.now(),
                status="failed",
                findings=[],
                summary={"error": str(e)}
            )
    
    async def _authenticate(self):
        """Authenticate with OpenVAS"""
        auth_data = {
            "username": self.username,
            "password": self.password
        }
        
        response = requests.post(
            f"{self.api_url}/auth",
            json=auth_data
        )
        
        if response.status_code != 200:
            raise Exception(f"OpenVAS authentication failed: {response.text}")
        
        self.token = response.json()["token"]
    
    async def _create_scan(self, target: str, options: Dict[str, Any]) -> str:
        """Create a new OpenVAS scan"""
        headers = {"Authorization": f"Bearer {self.token}"}
        
        scan_config = {
            "name": f"VulnRisk Scan - {target}",
            "targets": target,
            "scanner_id": options.get("scanner_id", "omp"),
            "schedule_id": "",
            "alterable": False,
            "host_ordering": "sequential",
            "ssh_credential_id": "",
            "smb_credential_id": "",
            "esxi_credential_id": "",
            "snmp_credential_id": "",
            "port_list_id": options.get("port_list_id", "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"),
            "task_id": "",
            "alert_ids": [],
            "comment": "Automated scan from VulnRisk"
        }
        
        response = requests.post(
            f"{self.api_url}/targets",
            headers=headers,
            json=scan_config
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to create OpenVAS scan: {response.text}")
        
        return response.json()["id"]
    
    async def _start_scan(self, scan_id: str):
        """Start an OpenVAS scan"""
        headers = {"Authorization": f"Bearer {self.token}"}
        
        response = requests.post(
            f"{self.api_url}/tasks/{scan_id}/start",
            headers=headers
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to start OpenVAS scan: {response.text}")
    
    async def _get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get OpenVAS scan results"""
        headers = {"Authorization": f"Bearer {self.token}"}
        
        response = requests.get(
            f"{self.api_url}/results",
            headers=headers,
            params={"task_id": scan_id}
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get OpenVAS scan results: {response.text}")
        
        results_data = response.json()
        return self.parse_results(results_data)
    
    def parse_results(self, results_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse OpenVAS scan results"""
        findings = []
        
        for result in results_data.get("results", []):
            finding = {
                "cve_id": result.get("nvt", {}).get("cve", []),
                "title": result.get("nvt", {}).get("name", ""),
                "description": result.get("nvt", {}).get("description", ""),
                "severity": self._convert_severity(result.get("severity", 0)),
                "cvss_score": result.get("severity", 0),
                "category": "vulnerability",
                "location": result.get("host", ""),
                "evidence": result.get("description", ""),
                "remediation": result.get("nvt", {}).get("solution", ""),
                "references": result.get("nvt", {}).get("references", []),
                "scanner": "openvas",
                "timestamp": datetime.now().isoformat()
            }
            findings.append(finding)
        
        return findings
    
    def _convert_severity(self, openvas_severity: float) -> str:
        """Convert OpenVAS severity to standard format"""
        if openvas_severity >= 7.0:
            return "critical"
        elif openvas_severity >= 4.0:
            return "high"
        elif openvas_severity >= 2.0:
            return "medium"
        else:
            return "low"
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for OpenVAS findings"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "scanner": "openvas"
        }

class TrivyScanner(BaseScanner):
    """Trivy scanner integration"""
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = f"trivy_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        # Build Trivy command
        cmd = ["trivy", "image", target, "--format", "json"]
        
        # Add optional parameters
        if options.get("severity"):
            cmd.extend(["--severity", options["severity"]])
        if options.get("ignore_unfixed"):
            cmd.append("--ignore-unfixed")
        
        try:
            # Run Trivy scan with timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)  # 5 minute timeout
            except asyncio.TimeoutError:
                process.kill()
                raise Exception("Trivy scan timed out after 5 minutes")
            
            if process.returncode != 0:
                raise Exception(f"Trivy scan failed: {stderr.decode()}")
            
            # Parse results
            raw_results = stdout.decode()
            findings = self.parse_results(raw_results)
            
            end_time = datetime.now()
            
            return ScanResult(
                scanner_type=ScannerType.TRIVY,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=end_time,
                status="completed",
                findings=findings,
                summary=self._generate_summary(findings)
            )
            
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.TRIVY,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=datetime.now(),
                status="failed",
                findings=[],
                summary={"error": str(e)}
            )
    
    def parse_results(self, raw_results: str) -> List[Dict[str, Any]]:
        """Parse Trivy JSON output"""
        findings = []
        
        try:
            results = json.loads(raw_results)
            
            for result in results.get("Results", []):
                target = result.get("Target", "")
                
                for vulnerability in result.get("Vulnerabilities", []):
                    finding = {
                        "cve_id": vulnerability.get("VulnerabilityID", ""),
                        "title": vulnerability.get("Title", ""),
                        "description": vulnerability.get("Description", ""),
                        "severity": vulnerability.get("Severity", "medium").lower(),
                        "cvss_score": vulnerability.get("CVSS", {}).get("nvd", {}).get("V3Score", 0),
                        "category": "vulnerability",
                        "location": target,
                        "evidence": vulnerability.get("InstalledVersion", ""),
                        "remediation": f"Update to version {vulnerability.get('FixedVersion', 'latest')}",
                        "references": vulnerability.get("References", []),
                        "scanner": "trivy",
                        "timestamp": datetime.now().isoformat()
                    }
                    findings.append(finding)
        
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for Trivy findings"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "scanner": "trivy"
        }

class ZAPScanner(BaseScanner):
    """OWASP ZAP scanner integration"""
    
    def __init__(self):
        self.zap_url = os.getenv("ZAP_URL", "http://localhost:8080")
        self.api_key = os.getenv("ZAP_API_KEY", "")
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = f"zap_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        try:
            # Spider scan
            await self._spider_scan(target)
            
            # Active scan
            await self._active_scan(target)
            
            # Get results
            findings = await self._get_scan_results(target)
            
            end_time = datetime.now()
            
            return ScanResult(
                scanner_type=ScannerType.ZAP,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=end_time,
                status="completed",
                findings=findings,
                summary=self._generate_summary(findings)
            )
            
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.ZAP,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=datetime.now(),
                status="failed",
                findings=[],
                summary={"error": str(e)}
            )
    
    async def _spider_scan(self, target: str):
        """Run ZAP spider scan"""
        params = {
            "url": target,
            "apikey": self.api_key
        }
        
        response = requests.get(
            f"{self.zap_url}/JSON/spider/action/scan",
            params=params
        )
        
        if response.status_code != 200:
            raise Exception(f"ZAP spider scan failed: {response.text}")
    
    async def _active_scan(self, target: str):
        """Run ZAP active scan"""
        params = {
            "url": target,
            "apikey": self.api_key
        }
        
        response = requests.get(
            f"{self.zap_url}/JSON/ascan/action/scan",
            params=params
        )
        
        if response.status_code != 200:
            raise Exception(f"ZAP active scan failed: {response.text}")
    
    async def _get_scan_results(self, target: str) -> List[Dict[str, Any]]:
        """Get ZAP scan results"""
        params = {
            "baseurl": target,
            "apikey": self.api_key
        }
        
        response = requests.get(
            f"{self.zap_url}/JSON/core/view/alerts",
            params=params
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get ZAP scan results: {response.text}")
        
        alerts_data = response.json()
        return self.parse_results(alerts_data)
    
    def parse_results(self, alerts_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse ZAP scan results"""
        findings = []
        
        for alert in alerts_data.get("alerts", []):
            finding = {
                "cve_id": alert.get("cweid", ""),
                "title": alert.get("name", ""),
                "description": alert.get("description", ""),
                "severity": self._convert_severity(alert.get("risk", "medium")),
                "cvss_score": self._get_cvss_score(alert.get("risk", "medium")),
                "category": "vulnerability",
                "location": alert.get("url", ""),
                "evidence": alert.get("evidence", ""),
                "remediation": alert.get("solution", ""),
                "references": alert.get("reference", []),
                "scanner": "zap",
                "timestamp": datetime.now().isoformat()
            }
            findings.append(finding)
        
        return findings
    
    def _convert_severity(self, zap_risk: str) -> str:
        """Convert ZAP risk to standard format"""
        risk_map = {
            "High": "high",
            "Medium": "medium", 
            "Low": "low",
            "Informational": "info"
        }
        return risk_map.get(zap_risk, "medium")
    
    def _get_cvss_score(self, risk: str) -> float:
        """Get CVSS score based on ZAP risk level"""
        risk_scores = {
            "High": 7.0,
            "Medium": 4.0,
            "Low": 2.0,
            "Informational": 0.0
        }
        return risk_scores.get(risk, 4.0)
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for ZAP findings"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "scanner": "zap"
        }

class SonarQubeScanner(BaseScanner):
    """SonarQube scanner integration"""
    
    def __init__(self):
        self.sonar_url = os.getenv("SONARQUBE_URL", "")
        self.token = os.getenv("SONARQUBE_TOKEN", "")
    
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        scan_id = f"sonarqube_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        try:
            # Create project
            project_key = await self._create_project(target, options)
            
            # Run analysis
            await self._run_analysis(project_key, target)
            
            # Get results
            findings = await self._get_scan_results(project_key)
            
            end_time = datetime.now()
            
            return ScanResult(
                scanner_type=ScannerType.SONARQUBE,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=end_time,
                status="completed",
                findings=findings,
                summary=self._generate_summary(findings)
            )
            
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.SONARQUBE,
                target=target,
                scan_id=scan_id,
                start_time=start_time,
                end_time=datetime.now(),
                status="failed",
                findings=[],
                summary={"error": str(e)}
            )
    
    async def _create_project(self, target: str, options: Dict[str, Any]) -> str:
        """Create a SonarQube project"""
        headers = {"Authorization": f"Bearer {self.token}"}
        
        project_data = {
            "name": f"VulnRisk Project - {target}",
            "project": options.get("project_key", f"vulnrisk-{datetime.now().strftime('%Y%m%d')}")
        }
        
        response = requests.post(
            f"{self.sonar_url}/api/projects/create",
            headers=headers,
            data=project_data
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to create SonarQube project: {response.text}")
        
        return project_data["project"]
    
    async def _run_analysis(self, project_key: str, target: str):
        """Run SonarQube analysis"""
        # This would typically involve running sonar-scanner
        # For now, we'll simulate the analysis
        pass
    
    async def _get_scan_results(self, project_key: str) -> List[Dict[str, Any]]:
        """Get SonarQube scan results"""
        headers = {"Authorization": f"Bearer {self.token}"}
        
        response = requests.get(
            f"{self.sonar_url}/api/issues/search",
            headers=headers,
            params={
                "componentKeys": project_key,
                "types": "VULNERABILITY"
            }
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get SonarQube scan results: {response.text}")
        
        issues_data = response.json()
        return self.parse_results(issues_data)
    
    def parse_results(self, issues_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse SonarQube scan results"""
        findings = []
        
        for issue in issues_data.get("issues", []):
            finding = {
                "cve_id": issue.get("rule", ""),
                "title": issue.get("message", ""),
                "description": issue.get("message", ""),
                "severity": self._convert_severity(issue.get("severity", "medium")),
                "cvss_score": self._get_cvss_score(issue.get("severity", "medium")),
                "category": "vulnerability",
                "location": issue.get("component", ""),
                "evidence": issue.get("message", ""),
                "remediation": issue.get("message", ""),
                "references": [],
                "scanner": "sonarqube",
                "timestamp": datetime.now().isoformat()
            }
            findings.append(finding)
        
        return findings
    
    def _convert_severity(self, sonar_severity: str) -> str:
        """Convert SonarQube severity to standard format"""
        severity_map = {
            "BLOCKER": "critical",
            "CRITICAL": "critical",
            "MAJOR": "high",
            "MINOR": "medium",
            "INFO": "info"
        }
        return severity_map.get(sonar_severity, "medium")
    
    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score based on SonarQube severity"""
        severity_scores = {
            "BLOCKER": 9.0,
            "CRITICAL": 8.0,
            "MAJOR": 6.0,
            "MINOR": 4.0,
            "INFO": 2.0
        }
        return severity_scores.get(severity, 4.0)
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for SonarQube findings"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "scanner": "sonarqube"
        } 