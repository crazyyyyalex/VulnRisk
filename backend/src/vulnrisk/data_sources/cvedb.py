"""Shodan CVEDB (https://cvedb.shodan.io) — backup CVE data source.

CVEDB is keyless and not rate limited the way NVD is, which makes it a good
standby for the two cases where NVD leaves us with nothing: the request was
throttled, or the CVE exists but NVD has not finished analysing it and so
publishes no CVSS score.

The trade-off: CVEDB exposes base scores but no CVSS vector string, so the
:class:`CVEData` it produces carries ``has_cvss_vector=False`` and leaves the
vector components as None. Consumers must fall back to neutral assumptions for
those instead of reading the placeholder values as measurements.
"""

import logging
import os
from typing import Any, Dict, Optional

import httpx

from .base import CVEData, CVEDataSource, calculate_age_days, detect_exploit_references
from .epss import EPSSData, calculate_threat_intelligence_factor

logger = logging.getLogger("vulnrisk.cvedb")

DEFAULT_BASE_URL = "https://cvedb.shodan.io"
DEFAULT_TIMEOUT_SECONDS = 10.0


class CVEDBClient(CVEDataSource):
    """Client for the Shodan CVEDB free vulnerability lookup API."""

    name = "cvedb"

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.base_url = (base_url or os.getenv("CVEDB_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout if timeout is not None else _env_float("CVEDB_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        self.client = client or httpx.AsyncClient(timeout=self.timeout)
        # Remembers the last raw payload so an EPSS lookup right after a CVE
        # lookup for the same ID does not cost a second round trip.
        self._last_payload: Optional[Dict[str, Any]] = None
        self._last_cve_id: Optional[str] = None

    async def get_rich_cve_data(self, cve_id: str) -> Optional[CVEData]:
        """Fetch comprehensive CVE data from CVEDB."""
        payload = await self._fetch(cve_id)
        if payload is None:
            return None
        return self._parse_cve_data(payload, cve_id)

    async def get_rich_epss_data(self, cve_id: str) -> Optional[EPSSData]:
        """Fetch EPSS data from CVEDB, used when FIRST.org is unreachable."""
        payload = await self._fetch(cve_id)
        if payload is None:
            return None

        epss_score = payload.get("epss")
        if epss_score is None:
            return None

        epss_score = float(epss_score)
        # CVEDB's ranking_epss is the EPSS percentile on the same 0-1 scale
        # FIRST.org uses, so it maps across without rescaling.
        percentile = float(payload.get("ranking_epss") or 0.0)

        return EPSSData({
            'cve_id': cve_id,
            'epss_score': epss_score,
            'percentile': percentile,
            'date': payload.get("published_time"),
            'threat_intelligence_factor': calculate_threat_intelligence_factor(epss_score, percentile),
        })

    async def _fetch(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """GET /cve/{cve_id}, returning the raw payload or None."""
        if self._last_cve_id == cve_id:
            return self._last_payload

        try:
            response = await self.client.get(f"{self.base_url}/cve/{cve_id}")
        except Exception as e:
            logger.error(f"Error fetching CVEDB data for {cve_id}: {e}")
            return None

        if response.status_code == 404:
            logger.info(f"CVEDB has no record for {cve_id}")
            payload = None
        elif response.status_code != 200:
            logger.warning(f"CVEDB returned {response.status_code} for {cve_id}")
            return None
        else:
            try:
                payload = response.json()
            except ValueError as e:
                logger.error(f"Malformed CVEDB response for {cve_id}: {e}")
                return None
            # CVEDB answers unknown IDs with an empty-ish body rather than 404.
            if not isinstance(payload, dict) or not payload.get("cve_id"):
                payload = None

        self._last_cve_id = cve_id
        self._last_payload = payload
        return payload

    def _parse_cve_data(self, payload: Dict[str, Any], cve_id: str) -> Optional[CVEData]:
        """Map a CVEDB payload onto the shared CVEData shape."""
        try:
            cvss_score = _first_present(payload, "cvss", "cvss_v4", "cvss_v3", "cvss_v2")
            if cvss_score is None:
                logger.info(f"CVEDB record for {cve_id} carries no CVSS score")
                return None

            references = [ref for ref in (payload.get("references") or []) if ref]
            published_date = payload.get("published_time")

            return CVEData({
                'cve_id': payload.get("cve_id", cve_id),
                'cvss_score': float(cvss_score),
                # CVEDB publishes scores without the vector string.
                'cvss_vector': None,
                'has_cvss_vector': False,
                'cvss_version': payload.get("cvss_version"),
                'published_date': published_date,
                # CVEDB exposes no last-modified timestamp.
                'modified_date': None,
                'vulnerability_age_days': calculate_age_days(published_date),
                'description': payload.get("summary") or "",
                'cpe_configurations': payload.get("cpes") or [],
                'references': references,
                'cisa_kev': bool(payload.get("kev", False)),
                'has_exploit_references': detect_exploit_references(references),
                # Left as None so downstream context helpers fall back to their
                # neutral defaults instead of treating absence as "NONE".
                'attack_vector': None,
                'attack_complexity': None,
                'privileges_required': None,
                'user_interaction': None,
                'scope': None,
                'confidentiality_impact': None,
                'integrity_impact': None,
                'availability_impact': None,
                'data_source': self.name,
                'ransomware_campaign': str(payload.get("ransomware_campaign") or "").lower() == "known",
                'remediation_guidance': payload.get("propose_action"),
            })
        except Exception as e:
            logger.error(f"Error parsing CVEDB data for {cve_id}: {e}")
            return None


def _first_present(payload: Dict[str, Any], *keys: str) -> Optional[float]:
    """Return the first non-null value among ``keys``."""
    for key in keys:
        value = payload.get(key)
        if value is not None:
            return value
    return None


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
