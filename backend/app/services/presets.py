"""Scan presets: a named bundle of CVE window, severities, and rate limit.

quick  - last 1 year of CVEs, critical and high only, faster rate
medium - last 3 or 5 years (medium3 / medium5), default severities and rate
full   - last 10 years, default severities and rate
deep   - all CVE years, default severities and rate
"""

from typing import Any

PRESETS: dict[str, dict[str, Any]] = {
    "quick":   {"cve_years": 1,    "severities": ["critical", "high"], "rate_limit": 150},
    "medium3": {"cve_years": 3,    "severities": None, "rate_limit": None},
    "medium5": {"cve_years": 5,    "severities": None, "rate_limit": None},
    "full":    {"cve_years": 10,   "severities": None, "rate_limit": None},
    "deep":    {"cve_years": None, "severities": None, "rate_limit": None},
}
