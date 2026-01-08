# layer1_scanner/report.py

from typing import List, Dict, Any


def build_host_report(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Optional: aggregate per-host counts from flat rows.
    Not used yet by backend, but kept for extension.
    """
    report: Dict[str, Any] = {}
    for r in rows:
        host = r["host"]
        if host not in report:
            report[host] = {"host": host, "vulnerability_count": 0}
        if r.get("cve"):
            report[host]["vulnerability_count"] += 1
    return report
