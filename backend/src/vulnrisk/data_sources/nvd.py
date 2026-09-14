"""NVD (National Vulnerability Database) — primary CVE data source.

NVD is authoritative and the only source here that publishes full CVSS
vectors, so it stays first in the chain. It is also the source most likely to
come back empty: unauthenticated callers get 5 requests per 30 seconds, and
freshly published CVEs sit in "Awaiting Analysis" with no CVSS score at all.
Both cases return None here and hand off to the backup provider configured in
:mod:`vulnrisk.data_sources.resolver`.
"""

import asyncio
import logging
import os
import time
from typing import Optional, Tuple

import httpx

from .base import (
    CVEData,
    CVEDataSource,
    calculate_age_days,
    detect_exploit_references,
)

logger = logging.getLogger("vulnrisk.nvd")

DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_RETRIES = 2
# NVD answers throttled callers with 403 as often as 429.
RETRYABLE_STATUS_CODES = frozenset({403, 429, 500, 502, 503, 504})

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_TTL_SECONDS = 6 * 60 * 60

# The KEV catalogue is a multi-megabyte feed and identical for every caller, so
# it is cached at module level rather than per client instance.
_kev_cache: Optional[Tuple[float, frozenset]] = None
_kev_lock = asyncio.Lock()


# Re-exported for backwards compatibility: callers and tests import CVEData
# from this module.
__all__ = ["CVEData", "NVDClient"]


class NVDClient(CVEDataSource):
    name = "nvd"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.timeout = timeout if timeout is not None else _env_float("NVD_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        self.max_retries = max_retries if max_retries is not None else _env_int("NVD_MAX_RETRIES", DEFAULT_MAX_RETRIES)
        self.client = client or httpx.AsyncClient(timeout=self.timeout)
        # Kept for backwards compatibility with callers that inspected it.
        self.cisa_kev_url = CISA_KEV_URL
        self._cisa_kev_cache = None

    async def get_cvss_score(self, cve_id: str) -> Optional[float]:
        """Fetch CVSS score from NVD API for a given CVE ID."""
        cve_data = await self.get_rich_cve_data(cve_id)
        return cve_data.cvss_score if cve_data else None

    async def get_rich_cve_data(self, cve_id: str) -> Optional[CVEData]:
        """Fetch comprehensive CVE data from NVD API."""
        headers = {"apiKey": self.api_key} if self.api_key else {}

        for attempt in range(self.max_retries + 1):
            try:
                response = await self.client.get(
                    f"{self.base_url}",
                    params={"cveId": cve_id},
                    headers=headers,
                )
            except Exception as e:
                logger.error(f"Error fetching CVE data for {cve_id}: {e}")
                if attempt < self.max_retries:
                    await asyncio.sleep(_backoff_seconds(attempt))
                    continue
                return None

            logger.info(f"NVD API status: {response.status_code}")

            if response.status_code == 200:
                try:
                    data = response.json()
                except ValueError as e:
                    logger.error(f"Malformed NVD response for {cve_id}: {e}")
                    return None
                return await self._parse_rich_cve_data(data, cve_id)

            if response.status_code in RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                delay = _backoff_seconds(attempt)
                logger.warning(
                    f"NVD returned {response.status_code} for {cve_id}; "
                    f"retrying in {delay}s (attempt {attempt + 1}/{self.max_retries})"
                )
                await asyncio.sleep(delay)
                continue

            logger.warning(f"NVD returned {response.status_code} for {cve_id}; giving up")
            return None

        return None

    async def _parse_rich_cve_data(self, nvd_data: dict, cve_id: str) -> Optional[CVEData]:
        """Parse comprehensive CVE data from NVD response."""
        try:
            items = nvd_data.get("vulnerabilities", [])
            if not items:
                return None

            vuln_item = items[0]
            cve_info = vuln_item.get("cve", {})
            metrics = cve_info.get("metrics", {})

            # Extract CVSS data (prefer v3.1 > v3.0 > v2.0)
            cvss_data = None
            cvss_score = None
            cvss_vector = None

            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    cvss_data = metrics[version][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString", "")
                    break

            if not cvss_score:
                # Typically "Awaiting Analysis" — the backup source often has a
                # score for these already.
                logger.info(f"NVD record for {cve_id} carries no CVSS score")
                return None

            # Extract dates and calculate age
            published_date = cve_info.get("published")
            modified_date = cve_info.get("lastModified")
            vulnerability_age_days = calculate_age_days(published_date)

            # Extract description
            descriptions = cve_info.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CPE configurations
            cpe_configs = []
            configurations = vuln_item.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            cpe_configs.append(cpe_match.get("criteria", ""))

            # Extract references and check for exploit indicators
            references = [ref.get("url", "") for ref in cve_info.get("references", [])]
            has_exploit_refs = detect_exploit_references(references)

            # Check CISA KEV status
            cisa_kev = await self._check_cisa_kev(cve_id)

            # Extract CVSS vector components for intelligent context determination
            cvss_data = cvss_data or {}

            return CVEData({
                'cve_id': cve_id,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'has_cvss_vector': bool(cvss_vector),
                'published_date': published_date,
                'modified_date': modified_date,
                'vulnerability_age_days': vulnerability_age_days,
                'description': description,
                'cpe_configurations': cpe_configs,
                'references': references,
                'cisa_kev': cisa_kev,
                'has_exploit_references': has_exploit_refs,
                'attack_vector': cvss_data.get("attackVector", "NETWORK"),
                'attack_complexity': cvss_data.get("attackComplexity", "LOW"),
                'privileges_required': cvss_data.get("privilegesRequired", "NONE"),
                'user_interaction': cvss_data.get("userInteraction", "NONE"),
                'scope': cvss_data.get("scope", "UNCHANGED"),
                'confidentiality_impact': cvss_data.get("confidentialityImpact", "NONE"),
                'integrity_impact': cvss_data.get("integrityImpact", "NONE"),
                'availability_impact': cvss_data.get("availabilityImpact", "NONE"),
                'data_source': self.name,
            })

        except Exception as e:
            logger.error(f"Error parsing CVE data: {e}")
            return None

    async def _check_cisa_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA Known Exploited Vulnerabilities catalog."""
        try:
            catalog = await self._get_cisa_kev_catalog()
            return cve_id in catalog
        except Exception as e:
            logger.error(f"Error checking CISA KEV for {cve_id}: {e}")
            return False

    async def _get_cisa_kev_catalog(self) -> frozenset:
        """Return the KEV CVE IDs, refreshing the shared cache when stale."""
        global _kev_cache

        cached = _kev_cache
        if cached and (time.monotonic() - cached[0]) < CISA_KEV_TTL_SECONDS:
            return cached[1]

        async with _kev_lock:
            # Another coroutine may have refreshed it while we waited.
            cached = _kev_cache
            if cached and (time.monotonic() - cached[0]) < CISA_KEV_TTL_SECONDS:
                return cached[1]

            catalog = frozenset()
            try:
                response = await self.client.get(CISA_KEV_URL)
                if response.status_code == 200:
                    kev_data = response.json()
                    catalog = frozenset(
                        vuln.get("cveID", "") for vuln in kev_data.get("vulnerabilities", [])
                    )
                else:
                    logger.warning(f"CISA KEV feed returned {response.status_code}")
            except Exception as e:
                logger.error(f"Error fetching CISA KEV feed: {e}")
                # Serve a stale catalogue rather than losing KEV status entirely.
                if cached:
                    return cached[1]

            _kev_cache = (time.monotonic(), catalog)
            self._cisa_kev_cache = catalog
            return catalog

    def _parse_cvss_score(self, nvd_data: dict) -> Optional[float]:
        """Legacy method for backward compatibility."""
        try:
            items = nvd_data.get("vulnerabilities", [])
            if not items:
                return None
            metrics = items[0].get("cve", {}).get("metrics", {})
            # Try CVSS v3.1, then v3.0, then v2.0
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    return metrics[version][0]["cvssData"]["baseScore"]
            return None
        except Exception:
            return None


def _backoff_seconds(attempt: int) -> float:
    """Exponential backoff: 2s, 4s, 8s ..."""
    return float(2 ** (attempt + 1))


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
