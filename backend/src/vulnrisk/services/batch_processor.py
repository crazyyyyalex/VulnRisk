import asyncio
import uuid
import time
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor
import logging

from ..models.batch import BatchVulnerability, BatchResult, BatchStatus, BatchProgress
from ..core.risk_calculator import EnhancedContextualFramework, VulnerabilityData
from ..data_sources.resolver import CVEIntelligenceResolver
from .cve_intelligence import resolve_nvd_api_key

logger = logging.getLogger(__name__)

class BatchProcessor:
    """High-performance batch vulnerability processor."""
    
    def __init__(self, customer_id: str = None):
        self.customer_id = customer_id
        self.calculator = EnhancedContextualFramework()
        self.max_concurrent = 50  # Limit concurrent API calls
        self.rate_limit_delay = 0.1  # 100ms between API calls

        # One resolver for the whole batch: it shares a lookup cache, so a CVE
        # repeated across rows costs a single round trip.
        nvd_api_key = resolve_nvd_api_key({"sub": customer_id} if customer_id else None)
        self.resolver = CVEIntelligenceResolver(nvd_api_key=nvd_api_key)
        
    async def process_batch(self, vulnerabilities: List[BatchVulnerability]) -> List[BatchResult]:
        """Process a batch of vulnerabilities with rate limiting and error handling."""
        results = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Process vulnerabilities in chunks for better performance
        chunk_size = 100
        for i in range(0, len(vulnerabilities), chunk_size):
            chunk = vulnerabilities[i:i + chunk_size]
            chunk_results = await self._process_chunk(chunk, semaphore)
            results.extend(chunk_results)
            
            # Rate limiting between chunks
            if i + chunk_size < len(vulnerabilities):
                await asyncio.sleep(self.rate_limit_delay)
                
        return results
    
    async def _process_chunk(self, chunk: List[BatchVulnerability], semaphore: asyncio.Semaphore) -> List[BatchResult]:
        """Process a chunk of vulnerabilities concurrently."""
        tasks = []
        for vuln in chunk:
            task = self._process_single_vulnerability(vuln, semaphore)
            tasks.append(task)
        
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _process_single_vulnerability(self, vuln: BatchVulnerability, semaphore: asyncio.Semaphore) -> BatchResult:
        """Process a single vulnerability with error handling."""
        async with semaphore:
            try:
                # Fetch CVSS and EPSS data across the provider chain
                resolved = await self.resolver.resolve(vuln.cve_id)

                if not resolved.found:
                    return BatchResult(
                        cve_id=vuln.cve_id,
                        risk_score=0.0,
                        priority="UNKNOWN",
                        timeline_days=0,
                        explanation=(
                            "Vulnerability data not found in any configured source "
                            f"({', '.join(resolved.attempted_sources) or 'none'})"
                        ),
                        components={},
                        status="error",
                        error="Data not available"
                    )

                cvss_score = resolved.cve_data.cvss_score
                epss_score = resolved.epss_data.epss_score
                
                # Create vulnerability data and calculate risk
                vuln_data = VulnerabilityData(
                    cve_id=vuln.cve_id,
                    cvss_score=cvss_score,
                    asset_criticality=vuln.asset_criticality,
                    epss_score=epss_score,
                    is_internet_facing=vuln.is_internet_facing
                )
                
                risk_result = self.calculator.calculate_risk(vuln_data)
                
                return BatchResult(
                    cve_id=vuln.cve_id,
                    risk_score=risk_result.score,
                    priority=risk_result.priority,
                    timeline_days=risk_result.timeline_days,
                    explanation=risk_result.explanation,
                    components=risk_result.components,
                    status="success"
                )
                
            except Exception as e:
                logger.error(f"Error processing {vuln.cve_id}: {str(e)}")
                return BatchResult(
                    cve_id=vuln.cve_id,
                    risk_score=0.0,
                    priority="ERROR",
                    timeline_days=0,
                    explanation=f"Processing error: {str(e)}",
                    components={},
                    status="error",
                    error=str(e)
                )

class BatchProgressTracker:
    """Track batch processing progress."""
    
    def __init__(self, batch_id: str, total_count: int):
        self.batch_id = batch_id
        self.total_count = total_count
        self.processed_count = 0
        self.success_count = 0
        self.error_count = 0
        self.start_time = time.time()
    
    def update_progress(self, processed: int, success: int, error: int):
        """Update progress counters."""
        self.processed_count = processed
        self.success_count = success
        self.error_count = error
    
    def get_progress(self) -> BatchProgress:
        """Get current progress status."""
        progress_percentage = (self.processed_count / self.total_count * 100) if self.total_count > 0 else 0
        
        # Estimate remaining time
        elapsed_time = time.time() - self.start_time
        if self.processed_count > 0:
            rate = self.processed_count / elapsed_time
            remaining_items = self.total_count - self.processed_count
            estimated_time_remaining = int(remaining_items / rate) if rate > 0 else None
        else:
            estimated_time_remaining = None
        
        return BatchProgress(
            batch_id=self.batch_id,
            status=BatchStatus.PROCESSING if self.processed_count < self.total_count else BatchStatus.COMPLETED,
            processed_count=self.processed_count,
            total_count=self.total_count,
            progress_percentage=progress_percentage,
            estimated_time_remaining=estimated_time_remaining
        ) 