# layer2_pipeline/tools/nvd_tool.py

import requests
import os
from typing import List, Dict, Any


class NVDTool:
    def __init__(self):
        self.api_key = os.getenv("NVD_API_KEY")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def query(self, cves: List[str]) -> Dict[str, Any]:
        if not cves:
            return {"skipped": True}

        results: Dict[str, Any] = {}
        headers = {}

        if self.api_key:
            headers["apiKey"] = self.api_key

        for cve in cves:
            params = {"cveId": cve}
            try:
                r = requests.get(self.base_url, params=params, headers=headers, timeout=10)
                results[cve] = r.json() if r.status_code == 200 else {}
            except Exception as e:
                results[cve] = {"error": str(e)}

        return results
