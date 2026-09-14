from vulnrisk.core.risk_calculator import EnhancedContextualFramework, VulnerabilityData


def test_critical_priority():
    framework = EnhancedContextualFramework()
    vuln = VulnerabilityData(
        cve_id="CVE-2025-1234",
        cvss_score=9.0,
        asset_criticality=10,
        epss_score=0.9,
        is_internet_facing=True,
    )
    result = framework.calculate_risk(vuln)
    assert result.priority == "MEDIUM"
    assert result.timeline_days == 21
    assert result.score > 50


def test_high_priority():
    framework = EnhancedContextualFramework()
    vuln = VulnerabilityData(
        cve_id="CVE-2025-5678",
        cvss_score=7.0,
        asset_criticality=7,
        epss_score=0.5,
        is_internet_facing=False,
    )
    result = framework.calculate_risk(vuln)
    assert result.priority == "LOW"
    assert result.timeline_days == 120
    assert 30 < result.score < 50


def test_medium_priority():
    framework = EnhancedContextualFramework()
    vuln = VulnerabilityData(
        cve_id="CVE-2025-9999",
        cvss_score=5.0,
        asset_criticality=5,
        epss_score=0.2,
        is_internet_facing=False,
    )
    result = framework.calculate_risk(vuln)
    assert result.priority == "INFORMATIONAL"
    assert result.timeline_days == 180
    assert 10 < result.score < 30


def test_low_priority():
    framework = EnhancedContextualFramework()
    vuln = VulnerabilityData(
        cve_id="CVE-2025-0001",
        cvss_score=1.0,
        asset_criticality=1,
        epss_score=0.01,
        is_internet_facing=False,
    )
    result = framework.calculate_risk(vuln)
    assert result.priority == "INFORMATIONAL"
    assert result.timeline_days == 180
    assert result.score < 10
