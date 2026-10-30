"""Explainable prioritization: each finding gets a level (P1-P4) and a reason."""

from vulnsift.trivy import Finding

EPSS_HIGH = 0.10  # 10% chance of exploitation in the next 30 days
SEVERE = ("CRITICAL", "HIGH")


def prioritize(f: Finding) -> None:
    """Set f.priority and f.reason by applying the rules in order."""
    if f.kev:
        f.priority, f.reason = "P1", "Known exploited (CISA KEV)"
    elif f.epss is not None and f.epss >= EPSS_HIGH:
        f.priority, f.reason = "P2", f"Likely exploited soon (EPSS {f.epss:.0%})"
    elif f.severity in SEVERE:
        f.priority, f.reason = "P3", f"Severe on paper ({f.severity}), no sign of exploitation"
    else:
        f.priority, f.reason = "P4", "Low risk for now"


def sort_key(f: Finding) -> tuple[str, int, float]:
    """Most urgent first; within a level, fixable first, then most likely exploited."""
    return (f.priority, 0 if f.fixed else 1, -(f.epss or 0))