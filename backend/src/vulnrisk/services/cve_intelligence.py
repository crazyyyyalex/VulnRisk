"""One entry point for CVE lookups shared by every API surface.

Before this existed, each endpoint repeated the same "read the customer's NVD
key, build a client, give up if NVD is silent" block. Routing them all through
:func:`fetch_cve_intelligence` means the backup provider chain, the cache and
the provenance reporting apply everywhere at once.
"""

import logging
import os
from typing import Any, Dict, Optional

from ..data_sources.resolver import CVEIntelligenceResolver, ResolvedCVEIntelligence

logger = logging.getLogger("vulnrisk.cve_intelligence")

NOT_FOUND_DETAIL = (
    "Vulnerability data not found. No configured data source "
    "(NVD, Shodan CVEDB) returned a CVSS score for this CVE."
)


def resolve_nvd_api_key(user: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Customer-specific NVD key when there is one, else the org-wide key."""
    customer_id = user.get("sub") if user else None

    if customer_id:
        try:
            from .api_key_manager import api_key_manager

            customer_key = api_key_manager.get_customer_default_key(customer_id, "nvd")
            if customer_key:
                return customer_key
        except Exception as e:
            logger.warning(f"Could not read customer NVD API key: {e}")

    return os.getenv("NVD_API_KEY")


async def fetch_cve_intelligence(
    cve_id: str,
    user: Optional[Dict[str, Any]] = None,
    nvd_api_key: Optional[str] = None,
) -> ResolvedCVEIntelligence:
    """Resolve a CVE across the configured provider chain.

    Always returns a result; check ``.found`` before using the data.
    """
    if nvd_api_key is None:
        nvd_api_key = resolve_nvd_api_key(user)

    resolver = CVEIntelligenceResolver(nvd_api_key=nvd_api_key)
    return await resolver.resolve(cve_id)


def build_cve_intelligence_payload(resolved: ResolvedCVEIntelligence) -> Dict[str, Any]:
    """Shape a resolved lookup into the ``cve_intelligence`` API field.

    Vector-derived fields are reported as None rather than a guess when the
    answering source did not publish a CVSS vector, so the UI can tell
    "not applicable" apart from "measured as none".
    """
    cve_data = resolved.cve_data
    epss_data = resolved.epss_data
    has_vector = bool(cve_data and cve_data.has_cvss_vector)

    def vector_field(attribute: str, default: Any) -> Any:
        if not has_vector:
            return None
        return getattr(cve_data, attribute, default)

    return {
        'epss_score': epss_data.epss_score if epss_data else 0,
        'epss_percentile': epss_data.percentile if epss_data else 0,
        'cvss_score': cve_data.cvss_score if cve_data else 0,
        'cvss_vector': (cve_data.cvss_vector or '') if cve_data else '',
        'cisa_kev': cve_data.cisa_kev if cve_data else False,
        'has_exploit_references': cve_data.has_exploit_references if cve_data else False,
        'published_date': cve_data.published_date if cve_data else None,
        'modified_date': cve_data.modified_date if cve_data else None,
        'vulnerability_age_days': cve_data.vulnerability_age_days if cve_data else 0,
        'attack_vector': vector_field('attack_vector', 'NETWORK'),
        'attack_complexity': vector_field('attack_complexity', 'LOW'),
        'privileges_required': vector_field('privileges_required', 'NONE'),
        'user_interaction': vector_field('user_interaction', 'NONE'),
        'scope': vector_field('scope', 'UNCHANGED'),
        'confidentiality_impact': vector_field('confidentiality_impact', 'NONE'),
        'integrity_impact': vector_field('integrity_impact', 'NONE'),
        'availability_impact': vector_field('availability_impact', 'NONE'),
        # Extras only some sources publish
        'ransomware_campaign': cve_data.ransomware_campaign if cve_data else False,
        'remediation_guidance': cve_data.remediation_guidance if cve_data else None,
        # Where the numbers above came from
        'data_source': resolved.cve_source,
        'epss_data_source': resolved.epss_source,
        'provenance': resolved.as_provenance(),
    }
