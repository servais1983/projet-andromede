"""Tests d'intégration — Flask API"""
import io
import pytest
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-ci")
os.environ.setdefault("FLASK_ENV", "testing")

from src.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestHealthAndStatus:
    def test_healthz(self, client):
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_status(self, client):
        r = client.get("/status")
        assert r.status_code == 200
        data = r.get_json()
        assert data["system"] == "operational"

    def test_index(self, client):
        r = client.get("/")
        assert r.status_code == 200


class TestUploadEndpoint:
    def _csv_bytes(self, content: str) -> io.BytesIO:
        return io.BytesIO(content.encode())

    def test_no_file(self, client):
        r = client.post("/upload")
        assert r.status_code == 400

    def test_wrong_type(self, client):
        data = {"file": (io.BytesIO(b"hello"), "test.txt")}
        r = client.post("/upload", data=data, content_type="multipart/form-data")
        assert r.status_code == 400

    def test_clean_csv(self, client):
        csv_content = "name,email\nAlice,alice@example.com\n"
        data = {"file": (self._csv_bytes(csv_content), "clean.csv")}
        r = client.post("/upload", data=data, content_type="multipart/form-data")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["threats_detected"] == 0

    def test_malicious_csv(self, client):
        csv_content = "cmd\nInvoke-Expression -Command malware\nwannacry ransomware\n"
        data = {"file": (self._csv_bytes(csv_content), "bad.csv")}
        r = client.post("/upload", data=data, content_type="multipart/form-data")
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["threats_detected"] > 0
        assert body["risk_score"] > 0
