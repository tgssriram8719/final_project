# layer2_pipeline/tools/virustotal_tool.py

import requests
import os


class VirusTotalTool:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")

    def query(self, ip: str):
        if not self.api_key or not ip:
            return {"skipped": True}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}
        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code != 200:
            return {"error": r.text}

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return stats
