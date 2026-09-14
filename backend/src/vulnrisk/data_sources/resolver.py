"""Ordered CVE lookup across multiple providers.

Callers ask for a CVE once and get back whatever the first provider that
answers produced, along with a record of which sources were consulted. This is
what keeps a throttled NVD, or a CVE that NVD has not analysed yet, from
surfacing to the user as "Vulnerability data not found".

Order is configurable with ``CVE_DATA_SOURCES`` (default ``nvd,cvedb``).
"""

import asyncio
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import CVEData, CVEDataSource
from .cvedb import CVEDBClient
from .epss import EPSSClient, EPSSData
from .nvd import NVDClient

logger = logging.getLogger("vulnrisk.resolver")

DEFAULT_SOURCE_ORDER = ("nvd", "cvedb")
DEFAULT_CACHE_TTL_SECONDS = 3600

# Providers that can also answer EPSS lookups when FIRST.org is unavailable.
_EPSS_CAPABLE_SOURCES = ("cvedb",)


class ResolvedCVEIntelligence:
    """Outcome of a lookup: the data plus where each piece came from."""

    def __init__(
        self,
        cve_id: str,
        cve_data: Optional[CVEData] = None,
        epss_data: Optional[EPSSData] = None,
        cve_source: Optional[str] = None,
        epss_source: Optional[str] = None,
        attempted_sources: Optional[List[str]] = None,
    ):
        self.cve_id = cve_id
        self.cve_data = cve_data
        self.epss_data = epss_data
        self.cve_source = cve_source
        self.epss_source = epss_source
        self.attempted_sources = attempted_sources or []

    @property
    def found(self) -> bool:
        """True when we have enough to score: CVSS plus an EPSS probability."""
        return self.cve_data is not None and self.epss_data is not None

    @property
    def used_fallback(self) -> bool:
        """True when the primary source did not answer the CVE lookup."""
        return bool(self.cve_source) and self.cve_source != DEFAULT_SOURCE_ORDER[0]

    @property
    def degraded_fields(self) -> List[str]:
        """Context fields the answering source could not supply."""
        if self.cve_data is None or self.cve_data.has_cvss_vector:
            return []
        return [
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "scope",
            "confidentiality_impact",
            "integrity_impact",
            "availability_impact",
        ]

    def as_provenance(self) -> Dict[str, Any]:
        """Serialisable summary for API responses and audit trails."""
        return {
            "cve_source": self.cve_source,
            "epss_source": self.epss_source,
            "attempted_sources": self.attempted_sources,
            "used_fallback": self.used_fallback,
            "degraded_fields": self.degraded_fields,
        }


class CVEIntelligenceResolver:
    """Walks the configured provider chain until one returns usable data."""

    def __init__(
        self,
        nvd_api_key: Optional[str] = None,
        source_order: Optional[List[str]] = None,
        cache_ttl_seconds: Optional[int] = None,
    ):
        self.nvd_api_key = nvd_api_key
        self.source_order = source_order or configured_source_order()
        self.cache_ttl_seconds = (
            cache_ttl_seconds
            if cache_ttl_seconds is not None
            else _env_int("CVE_CACHE_TTL_SECONDS", DEFAULT_CACHE_TTL_SECONDS)
        )
        self._sources: Dict[str, CVEDataSource] = {}
        self._epss_client: Optional[EPSSClient] = None

    async def resolve(self, cve_id: str) -> ResolvedCVEIntelligence:
        """Look up a CVE across the chain, caching the merged result."""
        cached = _result_cache.get(cve_id, self.cache_ttl_seconds)
        if cached is not None:
            logger.debug(f"Serving {cve_id} from resolver cache ({cached.cve_source})")
            return cached

        try:
            result = await self._resolve_uncached(cve_id)
        finally:
            await self.aclose()

        if result.found:
            _result_cache.set(cve_id, result, self.cache_ttl_seconds)
        return result

    async def _resolve_uncached(self, cve_id: str) -> ResolvedCVEIntelligence:
        attempted: List[str] = []
        cve_data: Optional[CVEData] = None
        cve_source: Optional[str] = None

        for source_name in self.source_order:
            source = self._get_source(source_name)
            if source is None:
                logger.warning(f"Unknown CVE data source '{source_name}' in CVE_DATA_SOURCES; skipping")
                continue

            attempted.append(source_name)
            try:
                cve_data = await source.get_rich_cve_data(cve_id)
            except Exception as e:
                logger.error(f"Source '{source_name}' raised while resolving {cve_id}: {e}")
                cve_data = None

            if cve_data is not None:
                cve_source = source_name
                if source_name != self.source_order[0]:
                    logger.info(f"Resolved {cve_id} from backup source '{source_name}'")
                break

            logger.info(f"Source '{source_name}' returned no data for {cve_id}")

        epss_data, epss_source = await self._resolve_epss(cve_id)

        if cve_data is None:
            logger.warning(f"No source could resolve {cve_id} (tried: {', '.join(attempted) or 'none'})")

        return ResolvedCVEIntelligence(
            cve_id=cve_id,
            cve_data=cve_data,
            epss_data=epss_data,
            cve_source=cve_source,
            epss_source=epss_source,
            attempted_sources=attempted,
        )

    async def _resolve_epss(self, cve_id: str) -> Tuple[Optional[EPSSData], Optional[str]]:
        """FIRST.org first, then any chain source that also carries EPSS."""
        if self._epss_client is None:
            self._epss_client = EPSSClient()

        try:
            epss_data = await self._epss_client.get_rich_epss_data(cve_id)
        except Exception as e:
            logger.error(f"EPSS lookup failed for {cve_id}: {e}")
            epss_data = None

        if epss_data is not None:
            return epss_data, "first.org"

        for source_name in self.source_order:
            if source_name not in _EPSS_CAPABLE_SOURCES:
                continue
            source = self._get_source(source_name)
            if source is None or not hasattr(source, "get_rich_epss_data"):
                continue
            try:
                epss_data = await source.get_rich_epss_data(cve_id)
            except Exception as e:
                logger.error(f"EPSS fallback via '{source_name}' failed for {cve_id}: {e}")
                continue
            if epss_data is not None:
                logger.info(f"Resolved EPSS for {cve_id} from backup source '{source_name}'")
                return epss_data, source_name

        return None, None

    def _get_source(self, name: str) -> Optional[CVEDataSource]:
        """Build providers lazily so an unused backup costs nothing."""
        if name in self._sources:
            return self._sources[name]

        if name == "nvd":
            source: CVEDataSource = NVDClient(api_key=self.nvd_api_key)
        elif name == "cvedb":
            source = CVEDBClient()
        else:
            return None

        self._sources[name] = source
        return source

    async def aclose(self) -> None:
        """Close every HTTP client this resolver opened."""
        for source in self._sources.values():
            try:
                await source.aclose()
            except Exception as e:
                logger.debug(f"Error closing source {getattr(source, 'name', source)}: {e}")
        self._sources = {}

        if self._epss_client is not None:
            try:
                await self._epss_client.client.aclose()
            except Exception as e:
                logger.debug(f"Error closing EPSS client: {e}")
            self._epss_client = None


class _ResultCache:
    """Small TTL cache. CVE data is public, so entries are shared globally."""

    def __init__(self) -> None:
        self._entries: Dict[str, Tuple[float, ResolvedCVEIntelligence]] = {}
        self._lock = asyncio.Lock()

    def get(self, cve_id: str, ttl_seconds: int) -> Optional[ResolvedCVEIntelligence]:
        if ttl_seconds <= 0:
            return None
        entry = self._entries.get(cve_id)
        if entry is None:
            return None
        stored_at, result = entry
        if (time.monotonic() - stored_at) >= ttl_seconds:
            self._entries.pop(cve_id, None)
            return None
        return result

    def set(self, cve_id: str, result: ResolvedCVEIntelligence, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        self._entries[cve_id] = (time.monotonic(), result)

    def clear(self) -> None:
        self._entries.clear()


_result_cache = _ResultCache()


def configured_source_order() -> List[str]:
    """Read CVE_DATA_SOURCES, falling back to the built-in order."""
    raw = os.getenv("CVE_DATA_SOURCES", "")
    order = [name.strip().lower() for name in raw.split(",") if name.strip()]
    return order or list(DEFAULT_SOURCE_ORDER)


def clear_cve_cache() -> None:
    """Drop every cached lookup. Exposed for tests and admin tooling."""
    _result_cache.clear()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
