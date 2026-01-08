# layer2_pipeline/input_parser.py

from typing import Dict, Any, List


class InputParser:
    """
    Parse different scan formats into normalized structure:

    {
      "asset": {...},
      "vulnerabilities": [
        {
          "cve": "...",
          "severity": "...",
          "cvss": 7.5,
          "service": "...",
          "port": 80,
          "product": "..."
        },
        ...
      ]
    }
    """

    def parse(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # Layer 1 normalized Nmap structure
        if "hosts" in data:
            return self._parse_from_hosts(data)

        # PDF-like / assets format
        if "assets" in data:
            return self._parse_pdf_format(data)

        # Already in standard structure
        return self._parse_standard_format(data)

    # ---------- formats ----------

    def _parse_standard_format(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "asset": data.get("asset", {}),
            "vulnerabilities": [
                {
                    "cve": v.get("cve"),
                    "severity": v.get("severity"),
                    "cvss": v.get("cvss_score") or v.get("cvss"),
                    "service": v.get("service"),
                    "port": v.get("port"),
                    "product": v.get("product"),
                }
                for v in data.get("vulnerabilities", [])
            ],
        }

    def _parse_pdf_format(self, data: Dict[str, Any]) -> Dict[str, Any]:
        vulns: List[Dict[str, Any]] = []
        asset_info: Dict[str, Any] = {}

        if data.get("assets"):
            asset = data["assets"][0]
            asset_info = {
                "ip": asset.get("ip", ""),
                "hostname": asset.get("hostname", ""),
                "state": asset.get("state", ""),
            }

        for asset in data.get("assets", []):
            for port_info in asset.get("open_ports", []):
                cve_data = port_info.get("cve")
                if not cve_data:
                    continue

                cve_id = cve_data.get("id") or cve_data.get("cve")
                if not cve_id or cve_id == "N/A":
                    continue

                cve_id = cve_id.strip()

                vulns.append(
                    {
                        "cve": cve_id,
                        "severity": cve_data.get("severity", "UNKNOWN"),
                        "cvss": cve_data.get("cvss") or cve_data.get("cvss_score"),
                        "service": port_info.get("service", ""),
                        "port": port_info.get("port_no"),
                        "product": port_info.get("product", ""),
                    }
                )

        return {"asset": asset_info, "vulnerabilities": vulns}

    def _parse_from_hosts(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse directly from Layer 1 normalized Nmap structure:

        {
          "hosts": {
            "ip": {
              "hostname": "...",
              "state": "...",
              "services": [
                {
                  "port": 22,
                  "service": "...",
                  "product": "...",
                  "vulnerabilities": [ { "cve": "...", "severity": "...", "cvss": ... } ]
                }
              ]
            }
          }
        }
        """
        hosts = data.get("hosts", {})
        asset_info: Dict[str, Any] = {}
        vulns: List[Dict[str, Any]] = []

        for ip, hdata in hosts.items():
            asset_info = {
                "ip": ip,
                "hostname": hdata.get("hostname", ip),
                "state": hdata.get("state", ""),
            }

            for svc in hdata.get("services", []):
                for v in svc.get("vulnerabilities", []):
                    vulns.append(
                        {
                            "cve": v.get("cve"),
                            "severity": v.get("severity", "UNKNOWN"),
                            "cvss": v.get("cvss"),
                            "service": svc.get("service"),
                            "port": svc.get("port"),
                            "product": svc.get("product"),
                        }
                    )
            break  # one asset per scan

        return {"asset": asset_info, "vulnerabilities": vulns}
