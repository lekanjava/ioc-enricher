import argparse
import os
import sys
from dotenv import load_dotenv
from rich.console import Console

from src.enricher import IOCEnricher
from src.reporter import save_json, save_csv, print_summary_table
from src.utils import load_iocs_from_file

load_dotenv()
console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        description="IOC Enricher -- Automated threat intel enrichment tool"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", help="Path to file containing IOCs")
    group.add_argument("--ioc", "-i", help="Single IOC to check")
    parser.add_argument("--output-dir", "-o", default="reports", help="Output directory")
    return parser.parse_args()


def main():
    args = parse_args()

    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSE_API_KEY")

    if not vt_key or not abuse_key:
        console.print("[red]Error:[/red] VT_API_KEY and ABUSE_API_KEY must be set in .env")
        sys.exit(1)

    if args.file:
        iocs = load_iocs_from_file(args.file)
        console.print(f"[bold]Loaded {len(iocs)} IOCs from {args.file}[/bold]")
    else:
        iocs = [args.ioc]
        console.print(f"[bold]Checking single IOC: {args.ioc}[/bold]")

    if not iocs:
        console.print("[yellow]No IOCs found. Exiting.[/yellow]")
        sys.exit(0)

    enricher = IOCEnricher(vt_key, abuse_key)
    results = enricher.enrich(iocs)

    print_summary_table(results)
    save_json(results, args.output_dir)
    save_csv(results, args.output_dir)

    console.print("\n[bold green]Done.[/bold green]")


if __name__ == "__main__":
    main()