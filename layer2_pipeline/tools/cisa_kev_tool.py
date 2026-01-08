# layer2_pipeline/tools/cisa_kev_tool.py

import requests
from typing import List, Dict, Any


class CISAKEVTool:
    """
    Simple checker against the CISA Known Exploited Vulnerabilities catalog.
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self._cache = None

    def _load_catalog(self):
        if self._cache is not None:
            return
        try:
            r = requests.get(self.KEV_URL, timeout=15)
            if r.status_code == 200:
                self._cache = r.json().get("vulnerabilities", [])
            else:
                self._cache = []
        except Exception:
            self._cache = []

    def query(self, cves: List[str]) -> Dict[str, Any]:
        self._load_catalog()
        if not self._cache:
            return {"skipped": True}

        kev_set = {v.get("cveID") for v in self._cache}
        hits = [cve for cve in cves if cve in kev_set]

        return {"kev_hits": hits}
