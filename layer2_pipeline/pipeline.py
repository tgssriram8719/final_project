# layer2_pipeline/pipeline.py

from datetime import datetime
from typing import Dict, Any, List

from .input_parser import InputParser
from .validator import Validator
from .risk_summary_builder import build_risk_input

from .tools.shodan_tool import ShodanTool
from .tools.virustotal_tool import VirusTotalTool
from .tools.nvd_tool import NVDTool
from .tools.vulners_tool import VulnersTool
from .tools.cisa_kev_tool import CISAKEVTool


class ThreatIntelPipeline:
    def __init__(self) -> None:
        self.parser = InputParser()
        self.validator = Validator()

        self.shodan = self._safe_init(ShodanTool, "Shodan")
        self.virustotal = self._safe_init(VirusTotalTool, "VirusTotal")
        self.nvd = self._safe_init(NVDTool, "NVD")
        self.vulners = self._safe_init(VulnersTool, "Vulners")
        self.cisa = self._safe_init(CISAKEVTool, "CISA KEV")

    def _safe_init(self, cls, name: str):
        try:
            return cls()
        except Exception as e:
            print(f"⚠️ Failed to initialize {name}: {e}")
            return None

    # -------- main API for backend --------

    def run_from_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry when called from FastAPI backend.
        Accepts scan dict (e.g., from Layer 1) and returns enriched document.
        """
        parsed = self.parser.parse(data)

        validation = self.validator.validate(parsed)
        if not validation["is_valid"]:
            return {"status": "failed", "errors": validation["errors"]}

        asset = parsed["asset"]
        vulns = parsed["vulnerabilities"]
        cves: List[str] = [v["cve"] for v in vulns if v.get("cve")]

        intel = {
            "shodan": self._safe_query(self.shodan, asset.get("ip")),
            "virustotal": self._safe_query(self.virustotal, asset.get("ip")),
            "nvd": self._safe_query(self.nvd, cves),
            "vulners": self._safe_query(self.vulners, cves),
            "cisa_kev": self._safe_query(self.cisa, cves),
        }

        level2 = {
            "asset": asset,
            "vulnerabilities": vulns,
            "intelligence": intel,
            "generated_at": datetime.utcnow().isoformat(),
        }

        risk_summary = build_risk_input(level2)

        combined = {
            "status": "success",
            "asset": asset,
            "vulnerabilities": vulns,
            "intelligence": intel,
            "summary": risk_summary,
            "generated_at": level2["generated_at"],
        }
        return combined

    # -------- helpers --------

    def _safe_query(self, tool, target):
        if tool is None:
            return {"skipped": True, "reason": "Tool not initialized"}
        if not target:
            return {"skipped": True, "reason": "No target provided"}

        try:
            return tool.query(target)
        except Exception as e:
            return {"error": f"{tool.__class__.__name__} exception: {str(e)}"}


# Singleton + function used by backend.main

_pipeline_singleton: ThreatIntelPipeline | None = None


def run_pipeline(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Function imported by backend.main:

        from layer2_pipeline import pipeline as l2_pipeline
        result = l2_pipeline.run_pipeline(payload)

    Accepts scan dict and returns combined Level 2 + risk summary.
    """
    global _pipeline_singleton
    if _pipeline_singleton is None:
        _pipeline_singleton = ThreatIntelPipeline()
    return _pipeline_singleton.run_from_dict(data)
