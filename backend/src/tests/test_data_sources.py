"""Tests for the CVE provider chain: Shodan CVEDB parsing and NVD fallback."""

import httpx
import pytest

from vulnrisk.data_sources.cvedb import CVEDBClient
from vulnrisk.data_sources.nvd import NVDClient
from vulnrisk.data_sources.resolver import (
    CVEIntelligenceResolver,
    clear_cve_cache,
    configured_source_order,
)

CVEDB_PAYLOAD = {
    "cve_id": "CVE-2021-44228",
    "summary": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
    "cvss": 10.0,
    "cvss_version": 3.0,
    "cvss_v2": 9.3,
    "cvss_v3": 10.0,
    "cvss_v4": None,
    "epss": 0.94,
    "ranking_epss": 0.99,
    "kev": True,
    "propose_action": "Upgrade Log4j to 2.17.1 or later.",
    "ransomware_campaign": "Known",
    "references": ["https://github.com/apache/logging-log4j2/pull/608"],
    "cpes": ["cpe:2.3:a:apache:log4j:2.0"],
    "published_time": "2021-12-10T10:15:09",
}


def _client_returning(payload, status_code=200, base_url="https://cvedb.shodan.io"):
    """Build a CVEDBClient whose transport replies with a canned response."""

    def handler(request: httpx.Request) -> httpx.Response:
        if status_code == 200:
            return httpx.Response(200, json=payload)
        return httpx.Response(status_code, text="error")

    transport = httpx.MockTransport(handler)
    return CVEDBClient(base_url=base_url, client=httpx.AsyncClient(transport=transport))


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_cve_cache()
    yield
    clear_cve_cache()


@pytest.mark.asyncio
async def test_cvedb_parses_full_payload():
    client = _client_returning(CVEDB_PAYLOAD)
    try:
        data = await client.get_rich_cve_data("CVE-2021-44228")
    finally:
        await client.aclose()

    assert data is not None
    assert data.cve_id == "CVE-2021-44228"
    assert data.cvss_score == 10.0
    assert data.cisa_kev is True
    assert data.data_source == "cvedb"
    assert data.ransomware_campaign is True
    assert data.remediation_guidance == "Upgrade Log4j to 2.17.1 or later."
    assert data.cpe_configurations == ["cpe:2.3:a:apache:log4j:2.0"]
    assert data.has_exploit_references is True  # github.com reference
    assert data.vulnerability_age_days > 0


@pytest.mark.asyncio
async def test_cvedb_flags_missing_cvss_vector():
    """CVEDB has no vector string, so vector components must read as unknown."""
    client = _client_returning(CVEDB_PAYLOAD)
    try:
        data = await client.get_rich_cve_data("CVE-2021-44228")
    finally:
        await client.aclose()

    assert data.has_cvss_vector is False
    assert data.cvss_vector is None
    assert data.attack_vector is None
    assert data.confidentiality_impact is None


@pytest.mark.asyncio
async def test_cvedb_falls_back_through_cvss_versions():
    payload = dict(CVEDB_PAYLOAD, cvss=None, cvss_v4=None, cvss_v3=7.5)
    client = _client_returning(payload)
    try:
        data = await client.get_rich_cve_data("CVE-2021-44228")
    finally:
        await client.aclose()

    assert data.cvss_score == 7.5


@pytest.mark.asyncio
async def test_cvedb_returns_none_without_any_score():
    payload = dict(CVEDB_PAYLOAD, cvss=None, cvss_v2=None, cvss_v3=None, cvss_v4=None)
    client = _client_returning(payload)
    try:
        assert await client.get_rich_cve_data("CVE-2021-44228") is None
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_cvedb_handles_unknown_cve():
    client = _client_returning({}, status_code=404)
    try:
        assert await client.get_rich_cve_data("CVE-1999-0000") is None
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_cvedb_supplies_epss_as_backup():
    client = _client_returning(CVEDB_PAYLOAD)
    try:
        epss = await client.get_rich_epss_data("CVE-2021-44228")
    finally:
        await client.aclose()

    assert epss is not None
    assert epss.epss_score == 0.94
    assert epss.percentile == 0.99
    # 0.94 is above the 0.3 "exploit code available" threshold
    assert epss.threat_intelligence_factor == 1.2


@pytest.mark.asyncio
async def test_nvd_returns_none_when_awaiting_analysis():
    """A CVE with no CVSS metrics must yield None so the chain moves on."""
    payload = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2025-0001", "metrics": {}, "descriptions": []}}
        ]
    }
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    client = NVDClient(client=httpx.AsyncClient(transport=transport))
    try:
        assert await client.get_rich_cve_data("CVE-2025-0001") is None
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_nvd_gives_up_after_retries_on_throttling():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url)
        return httpx.Response(429, text="rate limited")

    transport = httpx.MockTransport(handler)
    client = NVDClient(client=httpx.AsyncClient(transport=transport), max_retries=0)
    try:
        assert await client.get_rich_cve_data("CVE-2021-44228") is None
    finally:
        await client.aclose()

    assert len(calls) == 1  # max_retries=0 means a single attempt


class _StubSource:
    """Minimal CVEDataSource stand-in for chain-ordering tests."""

    def __init__(self, name, cve_data=None, epss_data=None, raises=False):
        self.name = name
        self._cve_data = cve_data
        self._epss_data = epss_data
        self._raises = raises
        self.calls = 0

    async def get_rich_cve_data(self, cve_id):
        self.calls += 1
        if self._raises:
            raise RuntimeError("boom")
        return self._cve_data

    async def get_rich_epss_data(self, cve_id):
        return self._epss_data

    async def aclose(self):
        pass


def _resolver_with(sources, epss_data=None):
    """Resolver wired to stub sources and a stub FIRST.org EPSS client."""
    resolver = CVEIntelligenceResolver(source_order=[s.name for s in sources], cache_ttl_seconds=0)
    resolver._sources = {s.name: s for s in sources}
    resolver._get_source = lambda name: resolver._sources.get(name)

    class _StubEPSS:
        client = None

        async def get_rich_epss_data(self, cve_id):
            return epss_data

    resolver._epss_client = _StubEPSS()
    return resolver


@pytest.mark.asyncio
async def test_resolver_prefers_primary_and_skips_backup(monkeypatch):
    from vulnrisk.data_sources.base import CVEData
    from vulnrisk.data_sources.epss import EPSSData

    primary = _StubSource("nvd", cve_data=CVEData({"cve_id": "CVE-1", "cvss_score": 7.0, "cvss_vector": "AV:N"}))
    backup = _StubSource("cvedb", cve_data=CVEData({"cve_id": "CVE-1", "cvss_score": 9.0}))
    resolver = _resolver_with([primary, backup], epss_data=EPSSData({"cve_id": "CVE-1", "epss_score": 0.4}))

    result = await resolver.resolve("CVE-1")

    assert result.found
    assert result.cve_source == "nvd"
    assert result.used_fallback is False
    assert backup.calls == 0  # backup never touched when primary answers


@pytest.mark.asyncio
async def test_resolver_falls_back_when_primary_is_empty():
    from vulnrisk.data_sources.base import CVEData
    from vulnrisk.data_sources.epss import EPSSData

    primary = _StubSource("nvd", cve_data=None)
    backup = _StubSource("cvedb", cve_data=CVEData({"cve_id": "CVE-1", "cvss_score": 9.0, "has_cvss_vector": False}))
    resolver = _resolver_with([primary, backup], epss_data=EPSSData({"cve_id": "CVE-1", "epss_score": 0.4}))

    result = await resolver.resolve("CVE-1")

    assert result.found
    assert result.cve_source == "cvedb"
    assert result.used_fallback is True
    assert result.attempted_sources == ["nvd", "cvedb"]
    assert "attack_vector" in result.degraded_fields


@pytest.mark.asyncio
async def test_resolver_falls_back_when_primary_raises():
    from vulnrisk.data_sources.base import CVEData
    from vulnrisk.data_sources.epss import EPSSData

    primary = _StubSource("nvd", raises=True)
    backup = _StubSource("cvedb", cve_data=CVEData({"cve_id": "CVE-1", "cvss_score": 9.0}))
    resolver = _resolver_with([primary, backup], epss_data=EPSSData({"cve_id": "CVE-1", "epss_score": 0.4}))

    result = await resolver.resolve("CVE-1")

    assert result.found
    assert result.cve_source == "cvedb"


@pytest.mark.asyncio
async def test_resolver_uses_backup_for_epss_when_first_org_is_down():
    from vulnrisk.data_sources.base import CVEData
    from vulnrisk.data_sources.epss import EPSSData

    primary = _StubSource("nvd", cve_data=CVEData({"cve_id": "CVE-1", "cvss_score": 7.0, "cvss_vector": "AV:N"}))
    backup = _StubSource("cvedb", epss_data=EPSSData({"cve_id": "CVE-1", "epss_score": 0.2}))
    # epss_data=None means the FIRST.org stub returns nothing.
    resolver = _resolver_with([primary, backup], epss_data=None)

    result = await resolver.resolve("CVE-1")

    assert result.found
    assert result.cve_source == "nvd"
    assert result.epss_source == "cvedb"
    assert result.epss_data.epss_score == 0.2


@pytest.mark.asyncio
async def test_resolver_reports_not_found_when_every_source_is_empty():
    primary = _StubSource("nvd", cve_data=None)
    backup = _StubSource("cvedb", cve_data=None)
    resolver = _resolver_with([primary, backup], epss_data=None)

    result = await resolver.resolve("CVE-1")

    assert not result.found
    assert result.cve_source is None
    assert result.attempted_sources == ["nvd", "cvedb"]


def test_source_order_is_configurable(monkeypatch):
    monkeypatch.setenv("CVE_DATA_SOURCES", "cvedb, nvd")
    assert configured_source_order() == ["cvedb", "nvd"]

    monkeypatch.setenv("CVE_DATA_SOURCES", "")
    assert configured_source_order() == ["nvd", "cvedb"]
