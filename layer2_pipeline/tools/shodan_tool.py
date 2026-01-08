# layer2_pipeline/tools/shodan_tool.py

import requests
import os
from dotenv import load_dotenv

load_dotenv()


class ShodanTool:
    def __init__(self):
        self.api_key = os.getenv("SHODAN_API_KEY")
        self.base_url = "https://api.shodan.io"

        if not self.api_key:
            print("❌ ERROR: SHODAN_API_KEY not found. Check your .env file")
        else:
            print(f"✅ Shodan API key loaded: {self.api_key[:8]}...")

    # -------- HOST LOOKUP --------

    def query(self, ip: str):
        """Query Shodan for a specific IP address (host lookup)."""
        if not self.api_key or not ip:
            return {"skipped": True, "reason": "Missing API key or IP"}

        print(f" 🔍 Shodan host lookup for IP: {ip}")
        url = f"{self.base_url}/shodan/host/{ip}"
        params = {"key": self.api_key}

        try:
            response = requests.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                location = data.get("location", {})

                vulns_data = data.get("vulns", [])
                if isinstance(vulns_data, list):
                    vulns_list = vulns_data
                elif isinstance(vulns_data, dict):
                    vulns_list = list(vulns_data.keys())
                else:
                    vulns_list = []

                result = {
                    "ip": data.get("ip_str"),
                    "ports": data.get("ports", []),
                    "org": data.get("org"),
                    "vulns": vulns_list,
                    "geo": {
                        "latitude": location.get("latitude"),
                        "longitude": location.get("longitude"),
                        "country": location.get("country_name"),
                        "city": location.get("city"),
                    },
                    "hostnames": data.get("hostnames", []),
                    "domains": data.get("domains", []),
                }

                print(" ✅ Shodan host lookup successful")
                return result

            elif response.status_code == 404:
                print(f" ⚠️ Shodan: IP {ip} not found")
                return {"error": "IP not found in Shodan", "status_code": 404}

            elif response.status_code == 401:
                print(" ❌ Shodan: Invalid API key")
                return {"error": "Invalid API key", "status_code": 401}

            else:
                error_msg = response.text[:200]
                print(f" ❌ Shodan error {response.status_code}: {error_msg}")
                return {
                    "error": f"HTTP {response.status_code}",
                    "details": error_msg,
                    "status_code": response.status_code,
                }

        except requests.exceptions.Timeout:
            print(" ❌ Shodan: Request timeout")
            return {"error": "Request timeout"}

        except Exception as e:
            print(f" ❌ Shodan exception: {str(e)}")
            return {"error": str(e)}

    # -------- SEARCH (used for map, optional) --------

    def search(self, query: str, limit: int = 100):
        """Search Shodan with detailed debugging."""
        if not self.api_key:
            return {
                "error": "No API key",
                "skipped": True,
                "message": "Set SHODAN_API_KEY in .env file",
            }

        print("\n🔍 Searching Shodan:")
        print(f" Query: '{query}'")
        print(f" Limit: {limit}")

        url = f"{self.base_url}/shodan/host/search"
        params = {
            "key": self.api_key,
            "query": query,
            "limit": min(limit, 100),
        }

        try:
            print(" Sending request to Shodan...")
            response = requests.get(url, params=params, timeout=30)
            print(f" Response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                total = data.get("total", 0)
                matches = data.get("matches", [])

                print(" ✅ Success!")
                print(f" Total results available: {total}")
                print(f" Matches returned: {len(matches)}")

                if matches:
                    first = matches[0]
                    print("\n First match example:")
                    print(f" - IP: {first.get('ip_str')}")
                    print(f" - Ports: {first.get('ports', [])[:5]}")
                    print(f" - Org: {first.get('org', 'Unknown')}")
                    loc = first.get("location", {})
                    print(
                        f" - Location: {loc.get('city', 'Unknown')}, {loc.get('country_name', 'Unknown')}"
                    )

                return data

            elif response.status_code == 401:
                print(" ❌ ERROR: Invalid API key (401 Unauthorized)")
                return {
                    "error": "Invalid API key",
                    "status_code": 401,
                    "message": "Check your SHODAN_API_KEY",
                }

            else:
                error_msg = response.text[:200]
                print(f" ❌ ERROR {response.status_code}: {error_msg}")
                return {"error": f"HTTP {response.status_code}", "details": error_msg}

        except requests.exceptions.Timeout:
            print(" ❌ ERROR: Request timeout")
            return {"error": "Request timeout"}

        except Exception as e:
            print(f" ❌ ERROR: {str(e)}")
            return {"error": str(e)}
