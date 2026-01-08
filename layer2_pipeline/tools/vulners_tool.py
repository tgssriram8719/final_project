# layer2_pipeline/tools/vulners_tool.py

import requests
import os
from typing import List, Dict, Any


class VulnersTool:
    def __init__(self):
        self.api_key = os.getenv("VULNERS_API_KEY")

    def query(self, cves: List[str]) -> Dict[str, Any]:
        if not self.api_key:
            return {"skipped": True}

        results: Dict[str, Any] = {}

        for cve in cves:
            url = "https://vulners.com/api/v3/search/lucene/"
            params = {"query": f"cveId:{cve}", "apiKey": self.api_key}
            r = requests.get(url, params=params, timeout=10)
            results[cve] = r.json() if r.status_code == 200 else {}

        return results
