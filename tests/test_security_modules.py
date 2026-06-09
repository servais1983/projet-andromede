"""
Tests des modules de sécurité réels :
  - QuantumShield (AES-256-GCM, Ed25519)
  - NeuralSandbox (isolation processus)
  - NebulaShield  (surveillance psutil)
  - Routes API    (/api/quantum/*, /api/blockchain/*, /api/nebula/*)
"""

import json
import os
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def quantum():
    from core.quantum.quantum_shield import QuantumShield
    return QuantumShield()


@pytest.fixture
def sandbox():
    from core.sandbox.neural_sandbox import NeuralSandbox, SandboxProfile
    return NeuralSandbox(SandboxProfile(wall_timeout_seconds=3.0))


@pytest.fixture
def nebula():
    from core.nebula.nebula_shield import NebulaShield
    return NebulaShield()


@pytest.fixture
def flask_client():
    os.environ["FLASK_ENV"] = "development"
    os.environ["SECRET_KEY"] = "test-key-pytest"
    from src.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ── QuantumShield ─────────────────────────────────────────────────────────────

class TestQuantumShield:

    def test_init(self, quantum):
        status = quantum.get_status()
        assert status["status"] == "operational"
        assert "AES-256-GCM" in status["algorithm"]
        assert len(status["node_public_key_x25519"]) == 64  # 32 bytes hex

    def test_key_generation(self, quantum):
        key_info = quantum.generate_key("pytest-key")
        assert key_info["key_id"] == "pytest-key"
        assert len(key_info["x25519_public"]) == 64
        assert len(key_info["ed25519_public"]) == 64

    def test_encrypt_decrypt_roundtrip(self, quantum):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        import secrets
        plaintext = b"Andromede AES-256-GCM test 2025"
        salt = secrets.token_bytes(32)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                   info=b"andromede-v1").derive(
            quantum.node_keypair.x25519_private.private_bytes_raw()
        )
        payload = quantum.encrypt(plaintext, key=key)
        assert payload.algorithm == "AES-256-GCM"
        assert len(payload.nonce) == 12
        decrypted = quantum.decrypt(payload, key)
        assert decrypted == plaintext

    def test_sign_verify_valid(self, quantum):
        data = b"signature test data"
        sig = quantum.sign(data)
        assert "signature_hex" in sig
        assert quantum.verify(data, sig["signature_hex"], sig["public_key_hex"])

    def test_sign_verify_tampered(self, quantum):
        data = b"original data"
        sig = quantum.sign(data)
        assert not quantum.verify(b"tampered data", sig["signature_hex"], sig["public_key_hex"])

    def test_secure_hash_sha3(self, quantum):
        h = quantum.secure_hash(b"test", "sha3_256")
        assert len(h) == 64
        assert h == quantum.secure_hash(b"test", "sha3_256")  # déterministe

    def test_encrypt_threat_signature(self, quantum):
        result = quantum.encrypt_threat_signature("SELECT * FROM users--")
        assert "ciphertext_hex" in result
        assert "signature_hex" in result
        assert "pattern_hash" in result
        assert result["algorithm"] == quantum.ALGORITHM


# ── NeuralSandbox ─────────────────────────────────────────────────────────────

class TestNeuralSandbox:

    def test_init(self, sandbox):
        status = sandbox.get_status()
        assert status["status"] == "operational"
        assert "resource.setrlimit" in str(status["isolation_mechanisms"])

    def test_run_echo(self, sandbox):
        result = sandbox.run_command(["echo", "hello sandbox"])
        assert result.success
        assert "hello sandbox" in result.stdout
        assert result.exit_code == 0

    def test_timeout_enforcement(self):
        from core.sandbox.neural_sandbox import NeuralSandbox, SandboxProfile
        sb = NeuralSandbox(SandboxProfile(wall_timeout_seconds=0.3))
        result = sb.run_command(["sleep", "10"])
        assert result.killed_reason == "timeout"
        assert result.wall_time_ms < 2000  # tué rapidement

    def test_unknown_command(self, sandbox):
        result = sandbox.run_command(["nonexistent_command_xyz"])
        assert not result.success
        assert "introuvable" in result.stderr.lower() or result.exit_code != 0

    def test_python_snippet_basic(self, sandbox):
        result = sandbox.run_python_snippet("print(6 * 7)")
        assert result.success
        assert "42" in result.stdout

    def test_python_snippet_cpu_bomb_contained(self):
        """Un snippet qui tente une boucle infinie est tué."""
        from core.sandbox.neural_sandbox import NeuralSandbox, SandboxProfile
        sb = NeuralSandbox(SandboxProfile(max_cpu_seconds=1, wall_timeout_seconds=3.0))
        result = sb.run_python_snippet("while True: pass")
        assert not result.success  # tué par RLIMIT_CPU ou timeout

    def test_stats_tracked(self, sandbox):
        sandbox.run_command(["echo", "a"])
        sandbox.run_command(["echo", "b"])
        assert sandbox.stats["executions"] >= 2


# ── NebulaShield ──────────────────────────────────────────────────────────────

class TestNebulaShield:

    def test_init(self, nebula):
        status = nebula.get_status()
        assert status["status"] == "operational"

    def test_system_snapshot(self, nebula):
        snap = nebula.system_snapshot()
        assert "cpu" in snap
        assert "memory" in snap
        assert "disk" in snap
        assert 0 <= snap["cpu"]["percent"] <= 100
        assert snap["memory"]["total_mb"] > 0

    def test_scan_processes(self, nebula):
        procs = nebula.scan_processes()
        assert len(procs) > 0
        # Vérifier la structure
        p = procs[0]
        assert hasattr(p, "pid")
        assert hasattr(p, "name")
        assert hasattr(p, "memory_rss_mb")

    def test_scan_network(self, nebula):
        nets = nebula.scan_network()
        # Peut être vide ou non — juste vérifier que ça ne lève pas d'exception
        assert isinstance(nets, list)

    def test_security_bubble(self, nebula):
        nebula.bubble.allow(1234)
        assert nebula.bubble.is_allowed(1234)
        assert not nebula.bubble.is_blocked(1234)
        nebula.bubble.block(1234)
        assert nebula.bubble.is_blocked(1234)
        assert not nebula.bubble.is_allowed(1234)

    def test_alerts_cleared(self, nebula):
        nebula._raise_alert("test", 9999, "test_proc", "unit test alert")
        assert len(nebula.alerts) == 1
        n = nebula.clear_alerts()
        assert n == 1
        assert len(nebula.alerts) == 0


# ── Routes API Flask ──────────────────────────────────────────────────────────

class TestAPIRoutes:

    def test_quantum_status(self, flask_client):
        r = flask_client.get("/api/quantum/status")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "operational"

    def test_quantum_encrypt(self, flask_client):
        r = flask_client.post("/api/quantum/encrypt",
            data=json.dumps({"data": "test message"}),
            content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "ciphertext_hex" in d
        assert d["algorithm"] == "AES-256-GCM"

    def test_quantum_sign(self, flask_client):
        r = flask_client.post("/api/quantum/sign",
            data=json.dumps({"data": "message to sign"}),
            content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "signature_hex" in d
        assert d["algorithm"] == "Ed25519"

    def test_blockchain_status(self, flask_client):
        r = flask_client.get("/api/blockchain/status")
        assert r.status_code == 200

    def test_blockchain_add_threat(self, flask_client):
        r = flask_client.post("/api/blockchain/add",
            data=json.dumps({"threat_data": {"type": "xss", "severity": "high"}}),
            content_type="application/json")
        assert r.status_code == 201
        d = r.get_json()
        assert d["success"]
        assert "block_hash" in d

    def test_nebula_status(self, flask_client):
        r = flask_client.get("/api/nebula/status")
        assert r.status_code == 200

    def test_nebula_snapshot(self, flask_client):
        r = flask_client.get("/api/nebula/snapshot")
        assert r.status_code == 200
        d = r.get_json()
        assert "system" in d
        assert "total_processes" in d
        assert d["total_processes"] > 0

    def test_sandbox_status(self, flask_client):
        r = flask_client.get("/api/sandbox/status")
        assert r.status_code == 200

    def test_status_all(self, flask_client):
        r = flask_client.get("/api/status/all")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "operational"
        assert "modules" in d

    def test_quantum_encrypt_missing_data(self, flask_client):
        r = flask_client.post("/api/quantum/encrypt",
            data=json.dumps({}),
            content_type="application/json")
        assert r.status_code == 400

    def test_blockchain_add_missing_data(self, flask_client):
        r = flask_client.post("/api/blockchain/add",
            data=json.dumps({}),
            content_type="application/json")
        assert r.status_code == 400
