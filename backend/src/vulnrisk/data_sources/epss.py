import httpx
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger("vulnrisk.epss")


def calculate_threat_intelligence_factor(epss_score: float, percentile: float) -> float:
    """
    Calculate threat intelligence factor based on EPSS score and percentile.
    Maps to your document's Threat_Intelligence_Factor values:
    1.5: Active exploitation campaigns detected
    1.2: Exploit code publicly available
    1.0: Standard EPSS scoring
    0.8: No known public exploits
    0.6: Theoretical vulnerability only

    Shared with backup EPSS providers (see data_sources/cvedb.py) so every
    source produces the same factor for the same numbers.
    """
    # Very high EPSS (top 5%) suggests active campaigns
    if percentile >= 95.0 and epss_score >= 0.7:
        return 1.5  # Active exploitation campaigns detected

    # High EPSS suggests exploit code availability
    elif epss_score >= 0.3:
        return 1.2  # Exploit code publicly available

    # Medium EPSS is standard scoring
    elif epss_score >= 0.05:
        return 1.0  # Standard EPSS scoring

    # Low EPSS suggests no known exploits
    elif epss_score >= 0.01:
        return 0.8  # No known public exploits

    # Very low EPSS is theoretical only
    else:
        return 0.6  # Theoretical vulnerability only


class EPSSData:
    """Rich EPSS data with threat intelligence context."""
    def __init__(self, data: Dict[str, Any]):
        self.cve_id = data.get('cve_id')
        self.epss_score = data.get('epss_score', 0.0)
        self.percentile = data.get('percentile', 0.0)
        self.date = data.get('date')
        self.threat_intelligence_factor = data.get('threat_intelligence_factor', 1.0)

class EPSSClient:
    def __init__(self):
        self.base_url = "https://api.first.org/data/v1/epss"
        self.client = httpx.AsyncClient()

    async def get_epss_score(self, cve_id: str) -> Optional[float]:
        """Fetch EPSS score from FIRST.org API for a given CVE ID."""
        epss_data = await self.get_rich_epss_data(cve_id)
        return epss_data.epss_score if epss_data else None

    async def get_rich_epss_data(self, cve_id: str) -> Optional[EPSSData]:
        """Fetch comprehensive EPSS data with threat intelligence context."""
        try:
            response = await self.client.get(
                f"{self.base_url}",
                params={"cve": cve_id}
            )

            if response.status_code == 200:
                data = response.json()
                return self._parse_rich_epss_data(data, cve_id)
            return None
        except Exception as e:
            logger.error(f"Error fetching EPSS data for {cve_id}: {e}")
            return None

    def _parse_rich_epss_data(self, epss_data: dict, cve_id: str) -> Optional[EPSSData]:
        """Parse EPSS data and determine threat intelligence factors."""
        try:
            data = epss_data.get("data", [])
            if not data:
                return None
            
            epss_item = data[0]
            epss_score = float(epss_item.get("epss", 0.0))
            percentile = float(epss_item.get("percentile", 0.0))
            date = epss_item.get("date")
            
            # Determine threat intelligence factor based on EPSS score and percentile
            threat_intel_factor = self._calculate_threat_intelligence_factor(epss_score, percentile)
            
            return EPSSData({
                'cve_id': cve_id,
                'epss_score': epss_score,
                'percentile': percentile,
                'date': date,
                'threat_intelligence_factor': threat_intel_factor
            })
            
        except Exception as e:
            logger.error(f"Error parsing EPSS data: {e}")
            return None

    def _calculate_threat_intelligence_factor(self, epss_score: float, percentile: float) -> float:
        """Delegate to the shared factor calculation."""
        return calculate_threat_intelligence_factor(epss_score, percentile)

    def _parse_epss_score(self, epss_data: dict) -> Optional[float]:
        """Legacy method for backward compatibility."""
        try:
            data = epss_data.get("data", [])
            if not data:
                return None
            return float(data[0]["epss"])
        except Exception:
            return None 