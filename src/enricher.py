from src.virustotal import VirusTotalClient
from src.abuseipdb import AbuseIPDBClient
from src.utils import detect_ioc_type, calculate_risk_score
from rich.console import Console
from rich.progress import track

console = Console()


class IOCEnricher:
    def __init__(self, vt_api_key: str, abuse_api_key: str):
        self.vt = VirusTotalClient(vt_api_key)
        self.abuse = AbuseIPDBClient(abuse_api_key)

    def enrich(self, iocs: list[str]) -> list[dict]:
        results = []

        for ioc in track(iocs, description="[cyan]Enriching IOCs..."):
            ioc_type = detect_ioc_type(ioc)

            if ioc_type == "unknown":
                console.print(f"[yellow]Skipping unknown IOC type: {ioc}[/yellow]")
                continue

            console.print(f"\n[bold]Checking:[/bold] {ioc} ([dim]{ioc_type}[/dim])")
            result = self._enrich_single(ioc, ioc_type)
            results.append(result)
            self.vt.sleep()

        return results

    def _enrich_single(self, ioc: str, ioc_type: str) -> dict:
        if ioc_type == "ip":
            vt_result = self.vt.check_ip(ioc)
        elif ioc_type == "domain":
            vt_result = self.vt.check_domain(ioc)
        elif ioc_type == "hash":
            vt_result = self.vt.check_hash(ioc)
        else:
            vt_result = {"malicious": 0, "total_engines": 0, "error": "unsupported"}

        if ioc_type == "ip":
            abuse_result = self.abuse.check_ip(ioc)
            abuse_score = abuse_result.get("abuse_confidence_score")
        else:
            abuse_result = None
            abuse_score = None

        risk = calculate_risk_score(
            vt_malicious=vt_result.get("malicious", 0),
            vt_total=vt_result.get("total_engines", 0),
            abuse_score=abuse_score
        )

        enriched = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "risk_score": risk["risk_score"],
            "verdict": risk["verdict"],
            "virustotal": {
                "malicious": vt_result.get("malicious", 0),
                "suspicious": vt_result.get("suspicious", 0),
                "total_engines": vt_result.get("total_engines", 0),
                "error": vt_result.get("error")
            },
            "abuseipdb": {
                "confidence_score": abuse_score,
                "total_reports": abuse_result.get("total_reports", 0) if abuse_result else None,
                "country": abuse_result.get("country_code") if abuse_result else None,
                "isp": abuse_result.get("isp") if abuse_result else None,
                "is_tor": abuse_result.get("is_tor", False) if abuse_result else None,
                "last_reported": abuse_result.get("last_reported") if abuse_result else None,
                "error": abuse_result.get("error") if abuse_result else "not_applicable"
            }
        }

        colour = {"MALICIOUS": "red", "SUSPICIOUS": "yellow", "CLEAN": "green"}
        v = enriched["verdict"]
        console.print(
            f"  Verdict: [{colour[v]}]{v}[/{colour[v]}] "
            f"(Risk score: {enriched['risk_score']}/100)"
        )

        return enriched