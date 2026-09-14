"""Shared contracts and helpers for CVE data sources.

Every provider returns the same :class:`CVEData` shape so that
:mod:`vulnrisk.data_sources.resolver` can fall back from one provider to the
next without callers needing to know which one answered.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

# Reference URLs containing any of these hint that public exploit code exists.
EXPLOIT_REFERENCE_INDICATORS = (
    "exploit",
    "poc",
    "metasploit",
    "exploit-db",
    "exploitdb",
    "github.com",
    "proof-of-concept",
    "vulnerability-lab",
)


def detect_exploit_references(references: Iterable[str]) -> bool:
    """Return True when any reference URL looks like public exploit material."""
    for url in references:
        lowered = (url or "").lower()
        if any(indicator in lowered for indicator in EXPLOIT_REFERENCE_INDICATORS):
            return True
    return False


def parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp, tolerating a trailing 'Z' and naive values."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def calculate_age_days(published_date: Optional[str]) -> int:
    """Days elapsed since publication, or 0 when the date is unusable."""
    published = parse_timestamp(published_date)
    if not published:
        return 0
    return max((datetime.now(timezone.utc) - published).days, 0)


class CVEData:
    """Rich CVE data, normalised across every data source.

    ``has_cvss_vector`` tells callers whether the vector components below are
    real or just placeholders. Sources such as Shodan CVEDB publish a base
    score without the vector, so consumers must not read ``attack_vector`` and
    friends as facts when this flag is False.
    """

    def __init__(self, data: Dict[str, Any]):
        self.cve_id = data.get('cve_id')
        self.cvss_score = data.get('cvss_score')
        self.cvss_vector = data.get('cvss_vector')
        self.cvss_version = data.get('cvss_version')
        self.published_date = data.get('published_date')
        self.modified_date = data.get('modified_date')
        self.vulnerability_age_days = data.get('vulnerability_age_days', 0)
        self.description = data.get('description', '')
        self.cpe_configurations = data.get('cpe_configurations', [])
        self.references = data.get('references', [])
        self.cisa_kev = data.get('cisa_kev', False)
        self.has_exploit_references = data.get('has_exploit_references', False)
        self.attack_vector = data.get('attack_vector', 'NETWORK')  # NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL
        self.attack_complexity = data.get('attack_complexity', 'LOW')  # LOW, HIGH
        self.privileges_required = data.get('privileges_required', 'NONE')  # NONE, LOW, HIGH
        self.user_interaction = data.get('user_interaction', 'NONE')  # NONE, REQUIRED
        self.scope = data.get('scope', 'UNCHANGED')  # UNCHANGED, CHANGED
        self.confidentiality_impact = data.get('confidentiality_impact', 'NONE')  # NONE, LOW, HIGH
        self.integrity_impact = data.get('integrity_impact', 'NONE')  # NONE, LOW, HIGH
        self.availability_impact = data.get('availability_impact', 'NONE')  # NONE, LOW, HIGH
        # Provenance and completeness
        self.data_source = data.get('data_source', 'nvd')
        self.has_cvss_vector = data.get('has_cvss_vector', bool(self.cvss_vector))
        # Optional enrichment some sources provide (Shodan CVEDB)
        self.ransomware_campaign = data.get('ransomware_campaign', False)
        self.remediation_guidance = data.get('remediation_guidance')


class CVEDataSource(ABC):
    """Interface every CVE provider implements so they are interchangeable."""

    #: Stable identifier used in configuration and provenance reporting.
    name: str = "unknown"

    @abstractmethod
    async def get_rich_cve_data(self, cve_id: str) -> Optional[CVEData]:
        """Return normalised CVE data, or None when this source has nothing."""

    async def get_cvss_score(self, cve_id: str) -> Optional[float]:
        """Convenience accessor used by callers that only need the base score."""
        cve_data = await self.get_rich_cve_data(cve_id)
        return cve_data.cvss_score if cve_data else None

    async def aclose(self) -> None:
        """Release the underlying HTTP client. Safe to call more than once."""
        client = getattr(self, "client", None)
        if client is not None:
            await client.aclose()
