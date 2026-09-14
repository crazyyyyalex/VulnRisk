import pytest
from httpx import ASGITransport, AsyncClient
import pytest_asyncio
from vulnrisk.api.main import app
from vulnrisk.data_sources.nvd import CVEData
from vulnrisk.data_sources.epss import EPSSData
from vulnrisk.data_sources.resolver import ResolvedCVEIntelligence


@pytest_asyncio.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _sample_cve_data(cve_id: str, cvss_score: float = 8.5) -> CVEData:
    return CVEData(
        {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "vulnerability_age_days": 30,
            "cisa_kev": False,
            "has_exploit_references": True,
        }
    )


def _sample_epss_data(cve_id: str, epss_score: float = 0.7) -> EPSSData:
    return EPSSData(
        {
            "cve_id": cve_id,
            "epss_score": epss_score,
            "percentile": 0.9,
        }
    )


@pytest.mark.asyncio
async def test_score_success(async_client, monkeypatch):
    async def fake_fetch(cve_id, user=None, nvd_api_key=None):
        return ResolvedCVEIntelligence(
            cve_id=cve_id,
            cve_data=_sample_cve_data(cve_id),
            epss_data=_sample_epss_data(cve_id),
            cve_source="nvd",
            epss_source="first.org",
            attempted_sources=["nvd"],
        )

    from vulnrisk.api import main

    monkeypatch.setattr(main, "fetch_cve_intelligence", fake_fetch)

    payload = {
        "cve_id": "CVE-2025-1234",
        "asset_criticality": 9,
        "is_internet_facing": True,
        "framework": "enhanced",
    }
    response = await async_client.post("/api/v1/score", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["cve_id"] == "CVE-2025-1234"
    assert data["priority"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
    assert data["risk_score"] > 0
    assert "explanation" in data
    assert data["cve_intelligence"]["data_source"] == "nvd"
    assert data["cve_intelligence"]["provenance"]["used_fallback"] is False


@pytest.mark.asyncio
async def test_score_uses_backup_source(async_client, monkeypatch):
    """A CVE only the backup source knows about still scores, and says so."""

    def _fallback_cve_data(cve_id):
        return CVEData(
            {
                "cve_id": cve_id,
                "cvss_score": 9.8,
                "cvss_vector": None,
                "has_cvss_vector": False,
                "vulnerability_age_days": 3,
                "cisa_kev": True,
                "has_exploit_references": True,
                "data_source": "cvedb",
                "attack_vector": None,
                "confidentiality_impact": None,
                "integrity_impact": None,
                "availability_impact": None,
            }
        )

    async def fake_fetch(cve_id, user=None, nvd_api_key=None):
        return ResolvedCVEIntelligence(
            cve_id=cve_id,
            cve_data=_fallback_cve_data(cve_id),
            epss_data=_sample_epss_data(cve_id),
            cve_source="cvedb",
            epss_source="cvedb",
            attempted_sources=["nvd", "cvedb"],
        )

    from vulnrisk.api import main

    monkeypatch.setattr(main, "fetch_cve_intelligence", fake_fetch)

    payload = {
        "cve_id": "CVE-2025-9999",
        "asset_criticality": 9,
        "is_internet_facing": True,
        "framework": "enhanced",
    }
    response = await async_client.post("/api/v1/score", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] > 0

    intel = data["cve_intelligence"]
    assert intel["data_source"] == "cvedb"
    assert intel["provenance"]["used_fallback"] is True
    # No CVSS vector from this source, so vector fields must read as unknown
    # rather than being reported as measured "NONE" values.
    assert intel["attack_vector"] is None
    assert intel["confidentiality_impact"] is None
    assert "confidentiality_impact" in intel["provenance"]["degraded_fields"]


@pytest.mark.asyncio
async def test_score_not_found(async_client, monkeypatch):
    async def fake_fetch(cve_id, user=None, nvd_api_key=None):
        return ResolvedCVEIntelligence(
            cve_id=cve_id,
            cve_data=None,
            epss_data=None,
            attempted_sources=["nvd", "cvedb"],
        )

    from vulnrisk.api import main

    monkeypatch.setattr(main, "fetch_cve_intelligence", fake_fetch)

    payload = {
        "cve_id": "CVE-2025-0000",
        "asset_criticality": 5,
        "is_internet_facing": False,
        "framework": "enhanced",
    }
    response = await async_client.post("/api/v1/score", json=payload)
    assert response.status_code == 404
    assert "Vulnerability data not found" in response.json()["detail"]


@pytest.mark.asyncio
async def test_data_sources_endpoint(async_client):
    response = await async_client.get("/api/v1/data-sources")
    assert response.status_code == 200
    data = response.json()
    assert data["primary"] == "nvd"
    assert "cvedb" in data["fallbacks"]
    # No probe requested, so no outbound calls were made.
    assert "probes" not in data
