import pytest
from src.utils import detect_ioc_type, calculate_risk_score, load_iocs_from_file
import tempfile
import os


class TestDetectIOCType:
    def test_valid_ip(self):
        assert detect_ioc_type("185.220.101.1") == "ip"

    def test_google_dns(self):
        assert detect_ioc_type("8.8.8.8") == "ip"

    def test_invalid_ip_octet(self):
        assert detect_ioc_type("999.1.1.1") == "unknown"

    def test_domain(self):
        assert detect_ioc_type("google.com") == "domain"

    def test_subdomain(self):
        assert detect_ioc_type("malware.evil.com") == "domain"

    def test_md5_hash(self):
        assert detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "hash"

    def test_sha256_hash(self):
        sha256 = "a" * 64
        assert detect_ioc_type(sha256) == "hash"

    def test_unknown(self):
        assert detect_ioc_type("not-an-ioc!!!") == "unknown"


class TestRiskScore:
    def test_clean_score(self):
        result = calculate_risk_score(0, 80, 0)
        assert result["verdict"] == "CLEAN"
        assert result["risk_score"] == 0

    def test_malicious_score(self):
        result = calculate_risk_score(70, 80, 100)
        assert result["verdict"] == "MALICIOUS"
        assert result["risk_score"] >= 70

    def test_no_abuse_data(self):
        result = calculate_risk_score(40, 80, None)
        assert result["verdict"] in ["SUSPICIOUS", "MALICIOUS"]

    def test_zero_engines(self):
        result = calculate_risk_score(0, 0, 0)
        assert result["risk_score"] == 0


class TestLoadIOCs:
    def test_load_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# comment\n")
            f.write("8.8.8.8\n")
            f.write("\n")
            f.write("google.com\n")
            tmpfile = f.name

        iocs = load_iocs_from_file(tmpfile)
        os.unlink(tmpfile)

        assert len(iocs) == 2
        assert "8.8.8.8" in iocs
        assert "google.com" in iocs