import requests
import time

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
        self.rate_limit_delay = 15

    def _get(self, endpoint: str) -> dict:
        url = f"{VT_BASE_URL}/{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                return {"error": "not_found", "status_code": 404}
            if response.status_code == 429:
                return {"error": "rate_limited", "status_code": 429}
            return {"error": str(e), "status_code": response.status_code}
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "status_code": None}

    def check_ip(self, ip: str) -> dict:
        data = self._get(f"ip_addresses/{ip}")
        return self._parse_result(data, ioc=ip, ioc_type="ip")

    def check_domain(self, domain: str) -> dict:
        data = self._get(f"domains/{domain}")
        return self._parse_result(data, ioc=domain, ioc_type="domain")

    def check_hash(self, file_hash: str) -> dict:
        data = self._get(f"files/{file_hash}")
        return self._parse_result(data, ioc=file_hash, ioc_type="hash")

    def _parse_result(self, data: dict, ioc: str, ioc_type: str) -> dict:
        if "error" in data:
            return {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "source": "virustotal",
                "error": data["error"],
                "malicious": 0,
                "suspicious": 0,
                "total_engines": 0,
                "raw": {}
            }
        try:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "source": "virustotal",
                "error": None,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "raw": stats
            }
        except (KeyError, TypeError):
            return {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "source": "virustotal",
                "error": "unexpected_response_format",
                "malicious": 0,
                "suspicious": 0,
                "total_engines": 0,
                "raw": {}
            }

    def sleep(self):
        time.sleep(self.rate_limit_delay)