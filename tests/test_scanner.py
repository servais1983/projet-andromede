"""Tests unitaires — CSVScanner"""
import csv
import os
import tempfile
import pytest
from src.main import CSVScanner


@pytest.fixture
def scanner():
    return CSVScanner()


@pytest.fixture
def clean_csv(tmp_path):
    """CSV propre sans menaces."""
    f = tmp_path / "clean.csv"
    f.write_text("name,email\nAlice,alice@example.com\nBob,bob@example.com\n")
    return str(f)


@pytest.fixture
def malicious_csv(tmp_path):
    """CSV avec injections SQL et commandes PS."""
    f = tmp_path / "malicious.csv"
    with open(f, "w", newline="") as fp:
        w = csv.writer(fp)
        w.writerow(["input", "value"])
        w.writerow(["sql", "SELECT * FROM users WHERE 1=1"])
        w.writerow(["cmd", "Invoke-Expression -Command 'malicious'"])
        w.writerow(["ransomware", "wannacry detected"])
    return str(f)


class TestCSVScanner:
    def test_scanner_instantiation(self, scanner):
        assert scanner is not None
        assert hasattr(scanner, "scan_file")

    def test_clean_file_no_threats(self, scanner, clean_csv):
        result = scanner.scan_file(clean_csv)
        assert result["total_score"] == 0
        assert len(result["results"]) == 0
        assert result["risk_level"] == "Aucun risque détecté"

    def test_malicious_file_detected(self, scanner, malicious_csv):
        result = scanner.scan_file(malicious_csv)
        assert result["total_score"] > 0
        assert len(result["results"]) > 0

    def test_critical_threat_detected(self, scanner, malicious_csv):
        result = scanner.scan_file(malicious_csv)
        severities = [r["severity"] for r in result["results"]]
        assert "critical" in severities

    def test_file_hash_computed(self, scanner, clean_csv):
        result = scanner.scan_file(clean_csv)
        assert len(result["file_hash"]) == 64  # SHA-256 hex

    def test_html_report_generated(self, scanner, malicious_csv, tmp_path):
        result = scanner.scan_file(malicious_csv)
        report_path = str(tmp_path / "report.html")
        scanner.generate_html_report(result, output_path=report_path)
        assert os.path.exists(report_path)
        content = open(report_path).read()
        assert "Andromède" in content
        assert "wannacry" in content.lower() or "ransomware" in content.lower()

    def test_empty_file(self, scanner, tmp_path):
        f = tmp_path / "empty.csv"
        f.write_text("")
        result = scanner.scan_file(str(f))
        # Should not crash
        assert "risk_level" in result

    def test_nonexistent_file(self, scanner):
        result = scanner.scan_file("/nonexistent/path/file.csv")
        assert "results" in result
