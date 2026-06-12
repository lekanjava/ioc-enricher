import re

# These are patterns that describe what each IOC type looks like
# re.compile() turns a text pattern into a usable search tool
IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()

    if IP_PATTERN.match(ioc):
        parts = ioc.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return "ip"

    if MD5_PATTERN.match(ioc):
        return "hash"

    if SHA1_PATTERN.match(ioc):
        return "hash"

    if SHA256_PATTERN.match(ioc):
        return "hash"

    if DOMAIN_PATTERN.match(ioc):
        return "domain"

    return "unknown"


def load_iocs_from_file(filepath: str) -> list[str]:
    iocs = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                iocs.append(line)
    return iocs


def calculate_risk_score(vt_malicious: int, vt_total: int, abuse_score: int) -> dict:
    if vt_total == 0:
        vt_ratio = 0
    else:
        vt_ratio = (vt_malicious / vt_total) * 100

    if abuse_score is None:
        final_score = round(vt_ratio)
    else:
        final_score = round((vt_ratio * 0.6) + (abuse_score * 0.4))

    if final_score >= 70:
        verdict = "MALICIOUS"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "risk_score": final_score,
        "verdict": verdict
    }