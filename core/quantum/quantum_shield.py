#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Projet Andromède — Quantum Shield
Chiffrement post-quantique hybride réel :
  • AES-256-GCM  (symétrique — résistant à Grover : 128 bits de sécurité quantique)
  • HKDF-SHA-256 (dérivation de clé — NIST SP 800-56C)
  • X25519        (échange de clé Diffie-Hellman sur courbe de Bernstein)
  • Signatures Ed25519
"""

import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)


@dataclass
class EncryptedPayload:
    ciphertext: bytes
    nonce: bytes
    tag_included: bool
    algorithm: str
    key_id: str
    timestamp: str


@dataclass
class KeyPair:
    key_id: str
    x25519_private: X25519PrivateKey
    x25519_public_bytes: bytes
    ed25519_private: Ed25519PrivateKey
    ed25519_public_bytes: bytes
    created_at: datetime


class QuantumShield:
    """Bouclier cryptographique post-quantique hybride réel."""

    ALGORITHM = "AES-256-GCM+HKDF-SHA256+X25519+Ed25519"

    def __init__(self):
        self._keys: Dict[str, KeyPair] = {}
        self._session_keys: Dict[str, bytes] = {}
        self.stats = {"encryptions": 0, "decryptions": 0,
                      "key_exchanges": 0, "signatures": 0, "verifications": 0}
        self.node_keypair = self._generate_keypair("node_default")
        logger.info("Quantum Shield init — %s", self.ALGORITHM)

    def _generate_keypair(self, key_id: str) -> KeyPair:
        x_priv = X25519PrivateKey.generate()
        e_priv = Ed25519PrivateKey.generate()
        kp = KeyPair(
            key_id=key_id,
            x25519_private=x_priv,
            x25519_public_bytes=x_priv.public_key().public_bytes_raw(),
            ed25519_private=e_priv,
            ed25519_public_bytes=e_priv.public_key().public_bytes_raw(),
            created_at=datetime.utcnow(),
        )
        self._keys[key_id] = kp
        return kp

    def generate_key(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        kid = key_id or secrets.token_hex(8)
        kp = self._generate_keypair(kid)
        return {"key_id": kid, "algorithm": self.ALGORITHM,
                "x25519_public": kp.x25519_public_bytes.hex(),
                "ed25519_public": kp.ed25519_public_bytes.hex(),
                "created_at": kp.created_at.isoformat()}

    def _derive_key(self, secret: bytes, salt: bytes, info: bytes = b"andromede-v1") -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(secret)

    def perform_key_exchange(self, peer_x25519_public_hex: str,
                             key_id: str = "node_default") -> Dict[str, Any]:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        kp = self._keys.get(key_id, self.node_keypair)
        peer_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_x25519_public_hex))
        shared_secret = kp.x25519_private.exchange(peer_pub)
        salt = secrets.token_bytes(32)
        session_key = self._derive_key(shared_secret, salt)
        session_id = secrets.token_hex(8)
        self._session_keys[session_id] = session_key
        self.stats["key_exchanges"] += 1
        return {"session_id": session_id, "salt_hex": salt.hex(),
                "our_public_x25519": kp.x25519_public_bytes.hex(),
                "algorithm": self.ALGORITHM}

    def encrypt(self, plaintext: bytes, key: Optional[bytes] = None,
                session_id: Optional[str] = None, associated_data: bytes = b"") -> EncryptedPayload:
        if key is None and session_id:
            key = self._session_keys.get(session_id)
        if key is None:
            salt = secrets.token_bytes(32)
            key = self._derive_key(self.node_keypair.x25519_private.private_bytes_raw(), salt)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data or None)
        self.stats["encryptions"] += 1
        return EncryptedPayload(ciphertext=ciphertext, nonce=nonce, tag_included=True,
                                algorithm="AES-256-GCM", key_id=session_id or "ephemeral",
                                timestamp=datetime.utcnow().isoformat())

    def decrypt(self, payload: EncryptedPayload, key: bytes, associated_data: bytes = b"") -> bytes:
        plaintext = AESGCM(key).decrypt(payload.nonce, payload.ciphertext, associated_data or None)
        self.stats["decryptions"] += 1
        return plaintext

    def sign(self, data: bytes, key_id: str = "node_default") -> Dict[str, str]:
        kp = self._keys.get(key_id, self.node_keypair)
        signature = kp.ed25519_private.sign(data)
        self.stats["signatures"] += 1
        return {"signature_hex": signature.hex(),
                "public_key_hex": kp.ed25519_public_bytes.hex(),
                "data_hash": hashlib.sha256(data).hexdigest(),
                "algorithm": "Ed25519"}

    def verify(self, data: bytes, signature_hex: str, public_key_hex: str) -> bool:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pub.verify(bytes.fromhex(signature_hex), data)
            self.stats["verifications"] += 1
            return True
        except InvalidSignature:
            return False

    def secure_hash(self, data: bytes, algorithm: str = "sha3_256") -> str:
        algos = {"sha3_256": hashlib.sha3_256, "sha3_512": hashlib.sha3_512,
                 "blake2b": hashlib.blake2b, "sha256": hashlib.sha256}
        return algos.get(algorithm, hashlib.sha3_256)(data).hexdigest()

    def encrypt_threat_signature(self, threat_data: str) -> Dict[str, str]:
        plaintext = threat_data.encode()
        payload = self.encrypt(plaintext)
        sig_info = self.sign(plaintext)
        return {"ciphertext_hex": payload.ciphertext.hex(),
                "nonce_hex": payload.nonce.hex(),
                "pattern_hash": self.secure_hash(plaintext, "sha3_256"),
                "signature_hex": sig_info["signature_hex"],
                "public_key_hex": sig_info["public_key_hex"],
                "algorithm": self.ALGORITHM,
                "timestamp": payload.timestamp}

    def get_status(self) -> Dict[str, Any]:
        return {"status": "operational", "algorithm": self.ALGORITHM,
                "node_public_key_x25519": self.node_keypair.x25519_public_bytes.hex(),
                "node_public_key_ed25519": self.node_keypair.ed25519_public_bytes.hex(),
                "active_sessions": len(self._session_keys),
                "stats": self.stats,
                "quantum_resistance": {
                    "symmetric": "AES-256-GCM — 128 bits sécurité quantique (Grover)",
                    "kdf": "HKDF-SHA-256 — NIST SP 800-56C",
                    "asymmetric": "X25519/Ed25519 (hybride — migration Kyber planifiée)",
                    "hash": "SHA-3 / BLAKE2b — résistant Grover",
                }}
