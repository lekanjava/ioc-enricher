# IOC Enricher

Automated threat intelligence enrichment tool for security analysts.

Takes a list of Indicators of Compromise (IPs, domains, file hashes) and
automatically queries VirusTotal and AbuseIPDB to determine if they are
malicious. Outputs a risk-scored JSON and CSV report.

---

## What Problem This Solves

Without this tool, a SOC analyst checking 10 suspicious IPs has to:
1. Open VirusTotal, paste each IP, read the result
2. Open AbuseIPDB, paste each IP, read the result
3. Manually combine the findings
4. Write up a report

That is 20 manual lookups and 30+ minutes of work.

With this tool:
```
python main.py --file iocs.txt
```
All 10 IOCs are checked, scored, and reported in under 3 minutes.

---

## Features

- Detects IOC type automatically (IP, domain, MD5/SHA1/SHA256 hash)
- Queries VirusTotal and AbuseIPDB in parallel
- Calculates a normalised 0-100 risk score
- Verdict: MALICIOUS / SUSPICIOUS / CLEAN
- Outputs full JSON report and flat CSV summary
- Colour-coded terminal output
- Runs automatically in GitHub Actions on every push

---

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/ioc-enricher.git
cd ioc-enricher
```

### 2. Create virtual environment
```bash
# Mac/Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Add API keys
```bash
cp .env.example .env
# Edit .env and add your real keys
```

Get free API keys from:
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register

---

## Usage

### Check a file of IOCs
```bash
python main.py --file iocs.txt
```

### Check a single IOC
```bash
python main.py --ioc 185.220.101.1
python main.py --ioc malware-test.com
python main.py --ioc 44d88612fea8a8f36de82e1278abb02f
```

### Specify output folder
```bash
python main.py --file iocs.txt --output-dir my_reports
```

---

## Risk Scoring

| Score | Verdict |
|---|---|
| 70 - 100 | MALICIOUS |
| 30 - 69 | SUSPICIOUS |
| 0 - 29 | CLEAN |

**Formula:**
- For IPs: `(VirusTotal malicious ratio × 60%) + (AbuseIPDB confidence × 40%)`
- For domains and hashes: `VirusTotal malicious ratio × 100%`

---

## Project Structure

```
ioc-enricher/
├── src/
│   ├── enricher.py      # Orchestrator - coordinates all API calls
│   ├── virustotal.py    # VirusTotal API client
│   ├── abuseipdb.py     # AbuseIPDB API client
│   ├── utils.py         # IOC type detection and risk scoring
│   └── reporter.py      # JSON and CSV output
├── tests/
│   └── test_enricher.py # Unit tests
├── .github/workflows/
│   └── scan.yml         # GitHub Actions CI/CD pipeline
├── main.py              # CLI entry point
├── iocs.txt             # Input IOC list
└── requirements.txt     # Python dependencies
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Tech Stack

- Python 3.14
- requests (HTTP API calls)
- python-dotenv (secure key management)
- rich (terminal formatting)
- pytest (unit testing)
- GitHub Actions (CI/CD automation)

---

## Author

Built as a security automation portfolio project demonstrating:
threat intelligence enrichment, API integration, CI/CD pipelines,
and secure credential handling.