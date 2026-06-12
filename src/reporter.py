import json
import csv
import os
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table

console = Console()


def save_json(results: list[dict], output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"ioc_report_{timestamp}.json")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_iocs": len(results),
        "summary": _build_summary(results),
        "results": results
    }

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)

    console.print(f"\n[green]JSON report saved:[/green] {filepath}")
    return filepath


def save_csv(results: list[dict], output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"ioc_report_{timestamp}.csv")

    fieldnames = [
        "ioc", "ioc_type", "verdict", "risk_score",
        "vt_malicious", "vt_total_engines",
        "abuse_confidence_score", "abuse_total_reports",
        "country", "isp", "is_tor", "last_reported"
    ]

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "ioc": r["ioc"],
                "ioc_type": r["ioc_type"],
                "verdict": r["verdict"],
                "risk_score": r["risk_score"],
                "vt_malicious": r["virustotal"]["malicious"],
                "vt_total_engines": r["virustotal"]["total_engines"],
                "abuse_confidence_score": r["abuseipdb"]["confidence_score"],
                "abuse_total_reports": r["abuseipdb"]["total_reports"],
                "country": r["abuseipdb"]["country"],
                "isp": r["abuseipdb"]["isp"],
                "is_tor": r["abuseipdb"]["is_tor"],
                "last_reported": r["abuseipdb"]["last_reported"],
            })

    console.print(f"[green]CSV report saved:[/green] {filepath}")
    return filepath


def print_summary_table(results: list[dict]):
    table = Table(title="IOC Enrichment Summary", show_lines=True)

    table.add_column("IOC", style="cyan", no_wrap=True)
    table.add_column("Type", style="dim")
    table.add_column("Verdict", justify="center")
    table.add_column("Risk Score", justify="center")
    table.add_column("VT Malicious", justify="center")
    table.add_column("Abuse Score", justify="center")
    table.add_column("Country", justify="center")

    colour_map = {"MALICIOUS": "red", "SUSPICIOUS": "yellow", "CLEAN": "green"}

    for r in results:
        verdict = r["verdict"]
        colour = colour_map.get(verdict, "white")
        table.add_row(
            r["ioc"],
            r["ioc_type"],
            f"[{colour}]{verdict}[/{colour}]",
            str(r["risk_score"]),
            str(r["virustotal"]["malicious"]),
            str(r["abuseipdb"]["confidence_score"] or "N/A"),
            str(r["abuseipdb"]["country"] or "N/A"),
        )

    console.print(table)


def _build_summary(results: list[dict]) -> dict:
    verdicts = [r["verdict"] for r in results]
    return {
        "malicious": verdicts.count("MALICIOUS"),
        "suspicious": verdicts.count("SUSPICIOUS"),
        "clean": verdicts.count("CLEAN"),
    }