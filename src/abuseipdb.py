import requests

ABUSE_BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        try:
            response = requests.get(
                f"{ABUSE_BASE_URL}/check",
                headers=self.headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                },
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_result(data, ip)

        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                return self._error_result(ip, "rate_limited")
            return self._error_result(ip, str(e))
        except requests.exceptions.RequestException as e:
            return self._error_result(ip, str(e))

    def _parse_result(self, data: dict, ip: str) -> dict:
        try:
            d = data["data"]
            return {
                "ioc": ip,
                "source": "abuseipdb",
                "error": None,
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country_code": d.get("countryCode", "Unknown"),
                "isp": d.get("isp", "Unknown"),
                "domain": d.get("domain", "Unknown"),
                "is_tor": d.get("isTor", False),
                "last_reported": d.get("lastReportedAt", None),
            }
        except (KeyError, TypeError):
            return self._error_result(ip, "unexpected_response_format")

    def _error_result(self, ip: str, error: str) -> dict:
        return {
            "ioc": ip,
            "source": "abuseipdb",
            "error": error,
            "abuse_confidence_score": None,
            "total_reports": 0,
            "country_code": "Unknown",
            "isp": "Unknown",
            "domain": "Unknown",
            "is_tor": False,
            "last_reported": None,
        }