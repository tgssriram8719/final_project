from datetime import datetime
from typing import List, Dict, Any

from .scanner import scan_target
from .vulnerability import enrich_hosts_with_vulnerabilities
from .utils import log, NMAP_ARGUMENTS


def run_scan(
    scan_type: str = "Normal",
    target: str = "scanme.nmap.org",
) -> List[Dict[str, Any]]:
    """
    Used by backend.main:/scan/run.

    Returns flat rows suitable for /nmap/results and Layer 2.
    """
    log(f"Scan started for target: {target} (scan_type={scan_type})", "INFO")

    hosts_dict = scan_target(target)
    hosts_dict = enrich_hosts_with_vulnerabilities(hosts_dict)

    rows: List[Dict[str, Any]] = []
    timestamp = datetime.utcnow().isoformat()

    for host_ip, host_data in hosts_dict.items():
        hostname = host_data.get("hostname", "")
        risk_summary = host_data.get("risk_summary", {})

        for svc in host_data.get("services", []):
            base_row = {
                "timestamp": timestamp,
                "scan_type": scan_type,
                "host": host_ip,
                "hostname": hostname,
                "port": svc.get("port"),
                "protocol": svc.get("protocol"),
                "state": svc.get("state"),
                "service": svc.get("service"),
                "product": svc.get("product"),
                "version": svc.get("version"),
                "top_severity": svc.get("security_summary", {}).get("top_severity", "NONE"),
                "total_host_vulns": risk_summary.get("total_vulnerabilities", 0),
                "host_overall_risk": risk_summary.get("overall_risk", "INFO"),
                "host_risk_points": risk_summary.get("risk_points", 0),
                "command": f"nmap {NMAP_ARGUMENTS} -oX -",
                "target": target,
            }

            vulns = svc.get("vulnerabilities", []) or []
            if vulns:
                for v in vulns:
                    row = base_row.copy()
                    row.update(
                        {
                            "cve": v.get("cve"),
                            "cvss": v.get("cvss"),
                            "severity": v.get("severity"),
                        }
                    )
                    rows.append(row)
            else:
                rows.append(base_row)

    log(f"Scan completed successfully with {len(rows)} rows", "INFO")
    return rows
