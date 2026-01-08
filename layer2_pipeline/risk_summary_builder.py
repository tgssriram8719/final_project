# layer2_pipeline/risk_summary_builder.py

from typing import Dict, Any, List


def build_risk_input(level2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a simple risk summary per asset from Level 2 data.
    """
    asset = level2.get("asset", {})
    vulns: List[Dict[str, Any]] = level2.get("vulnerabilities", [])

    total = len(vulns)
    high = sum(1 for v in vulns if str(v.get("severity", "")).upper() == "HIGH")
    critical = sum(1 for v in vulns if str(v.get("severity", "")).upper() == "CRITICAL")
    medium = sum(1 for v in vulns if str(v.get("severity", "")).upper() == "MEDIUM")

    risk_score = critical * 5 + high * 3 + medium * 2

    overall = "LOW"
    if risk_score >= 20:
        overall = "HIGH"
    elif risk_score >= 10:
        overall = "MEDIUM"

    return {
        "asset": asset,
        "counts": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
        },
        "risk_score": risk_score,
        "overall_risk": overall,
    }
