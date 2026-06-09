#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Projet Andromède — Andromeda Chain
Vraie blockchain légère : SHA-256, proof-of-work, Merkle tree,
validation de chaîne, persistance JSON, API REST entre nœuds.
"""

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Structures de données ─────────────────────────────────────────────────────

@dataclass
class ThreatSignature:
    sig_id: str
    threat_type: str
    sha256_hash: str
    pattern_hash: str   # hash du pattern, pas le pattern brut
    severity: str
    confidence: float
    source_node: str
    timestamp: str

@dataclass
class Block:
    index: int
    timestamp: str
    signatures: List[Dict]
    previous_hash: str
    merkle_root: str
    nonce: int
    difficulty: int
    hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()


# ── Merkle Tree ───────────────────────────────────────────────────────────────

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def merkle_root(items: List[str]) -> str:
    """Calcule la racine Merkle d'une liste de hashes."""
    if not items:
        return _sha256("empty")
    layer = [_sha256(i) for i in items]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])   # duplique le dernier si impair
        layer = [_sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


# ── Andromeda Chain ───────────────────────────────────────────────────────────

class AndromedaChain:
    """
    Blockchain légère pour le partage décentralisé de signatures de menaces.

    • Proof-of-Work : cible un hash commençant par `difficulty` zéros
    • Merkle tree : garantit l'intégrité de chaque bloc
    • Persistance JSON : survie au redémarrage
    • Validation complète : index, hash précédent, PoW, Merkle
    """

    CHAIN_FILE = Path(__file__).parent.parent.parent / "config" / "andromeda_chain.json"
    DIFFICULTY  = int(os.environ.get("CHAIN_DIFFICULTY", "3"))   # 3 zéros ≈ <1s/bloc

    def __init__(self):
        self.chain: List[Block] = []
        self.pending: List[ThreatSignature] = []
        self.peers: List[str] = []
        self._lock = threading.Lock()
        self.node_id = hashlib.sha256(
            f"{os.getpid()}-{time.time()}".encode()
        ).hexdigest()[:16]
        self.stats = {"blocks_mined": 0, "signatures_shared": 0, "peers": 0}

        self.CHAIN_FILE.parent.mkdir(exist_ok=True)
        self._load_or_genesis()
        logger.info("⛓️  Andromeda Chain initialisée — %d bloc(s), nœud %s",
                    len(self.chain), self.node_id)

    # ── Persistance ───────────────────────────────────────────────────────────

    def _load_or_genesis(self):
        if self.CHAIN_FILE.exists():
            try:
                data = json.loads(self.CHAIN_FILE.read_text())
                self.chain = [Block(**b) for b in data]
                if self._validate_chain():
                    logger.info("Chaîne chargée et validée (%d blocs)", len(self.chain))
                    return
                logger.warning("Chaîne corrompue — recréation du bloc genesis")
            except Exception as exc:
                logger.warning("Erreur lecture chaîne: %s", exc)
        self.chain = [self._genesis()]
        self._save()

    def _save(self):
        self.CHAIN_FILE.write_text(
            json.dumps([asdict(b) for b in self.chain], indent=2)
        )

    # ── Genesis ───────────────────────────────────────────────────────────────

    def _genesis(self) -> Block:
        b = Block(
            index=0,
            timestamp=datetime.utcnow().isoformat(),
            signatures=[],
            previous_hash="0" * 64,
            merkle_root=merkle_root([]),
            nonce=0,
            difficulty=self.DIFFICULTY,
        )
        b.hash = b.compute_hash()
        return b

    # ── Proof of Work ─────────────────────────────────────────────────────────

    def _mine(self, block: Block) -> Block:
        target = "0" * block.difficulty
        nonce = 0
        t0 = time.time()
        while True:
            block.nonce = nonce
            h = block.compute_hash()
            if h.startswith(target):
                block.hash = h
                elapsed = time.time() - t0
                logger.info("⛏  Bloc #%d miné en %.2fs (nonce=%d hash=…%s)",
                            block.index, elapsed, nonce, h[-8:])
                return block
            nonce += 1
            if nonce % 100_000 == 0:
                logger.debug("Mining bloc #%d — nonce=%d", block.index, nonce)

    # ── API publique ──────────────────────────────────────────────────────────

    def add_signature(self, sig: ThreatSignature):
        """Ajoute une signature à la file d'attente."""
        with self._lock:
            self.pending.append(sig)
            self.stats["signatures_shared"] += 1
            if len(self.pending) >= 5:        # mine automatiquement si ≥ 5
                self._flush_pending()

    def mine_block(self, force: bool = False) -> Optional[Block]:
        """Mine un bloc avec les signatures en attente."""
        with self._lock:
            if not self.pending and not force:
                return None
            return self._flush_pending()

    def _flush_pending(self) -> Block:
        sigs = self.pending[:]
        self.pending = []

        previous = self.chain[-1]
        sig_dicts = [asdict(s) for s in sigs]
        mr = merkle_root([json.dumps(s, sort_keys=True) for s in sig_dicts])

        block = Block(
            index=len(self.chain),
            timestamp=datetime.utcnow().isoformat(),
            signatures=sig_dicts,
            previous_hash=previous.hash,
            merkle_root=mr,
            nonce=0,
            difficulty=self.DIFFICULTY,
        )
        mined = self._mine(block)
        self.chain.append(mined)
        self.stats["blocks_mined"] += 1
        self._save()
        return mined

    # ── Validation ────────────────────────────────────────────────────────────

    def _validate_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            # 1. Hash précédent cohérent
            if curr.previous_hash != prev.hash:
                logger.error("Bloc #%d — previous_hash invalide", i)
                return False

            # 2. Hash du bloc valide (PoW)
            if curr.hash != curr.compute_hash():
                logger.error("Bloc #%d — hash altéré", i)
                return False

            # 3. Preuve de travail
            if not curr.hash.startswith("0" * curr.difficulty):
                logger.error("Bloc #%d — PoW insuffisant", i)
                return False

            # 4. Merkle root
            expected_mr = merkle_root([
                json.dumps(s, sort_keys=True) for s in curr.signatures
            ])
            if curr.merkle_root != expected_mr:
                logger.error("Bloc #%d — Merkle root altéré", i)
                return False

        return True

    def is_valid(self) -> bool:
        return self._validate_chain()

    # ── Stats & export ────────────────────────────────────────────────────────

    def get_chain_info(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "length": len(self.chain),
            "difficulty": self.DIFFICULTY,
            "pending_signatures": len(self.pending),
            "is_valid": self._validate_chain(),
            "latest_block": {
                "index": self.chain[-1].index,
                "hash": self.chain[-1].hash,
                "timestamp": self.chain[-1].timestamp,
                "signature_count": len(self.chain[-1].signatures),
            } if self.chain else None,
            "stats": self.stats,
        }

    def get_all_signatures(self) -> List[Dict]:
        """Retourne toutes les signatures partagées sur la chaîne."""
        out = []
        for block in self.chain[1:]:   # skip genesis
            out.extend(block.signatures)
        return out

    def start_mining(self):
        """Lance un thread de minage en arrière-plan (toutes les 60s)."""
        def _loop():
            while True:
                time.sleep(60)
                try:
                    blk = self.mine_block(force=False)
                    if blk:
                        logger.info("Auto-minage bloc #%d", blk.index)
                except Exception as exc:
                    logger.warning("Erreur auto-minage: %s", exc)

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        logger.info("Thread de minage démarré")

    def get_status(self) -> dict:
        """Alias standardisé pour get_chain_info."""
        return self.get_chain_info()

    def get_chain(self):
        """Retourne la liste des blocs."""
        return list(self._chain)

    def add_threat(self, threat_data) -> "Block":
        """Ajoute une menace et mine immédiatement si nécessaire."""
        import json as _json
        import datetime as _dt
        if isinstance(threat_data, dict):
            payload = _json.dumps(threat_data, ensure_ascii=False, sort_keys=True)
        else:
            payload = str(threat_data)
        threat_type = (threat_data.get("type", "unknown")
                       if isinstance(threat_data, dict) else "unknown")
        severity = (threat_data.get("severity", "medium")
                    if isinstance(threat_data, dict) else "medium")
        sig = ThreatSignature(
            sig_id=_sha256(payload)[:16],
            threat_type=threat_type,
            sha256_hash=_sha256(payload),
            pattern_hash=_sha256(payload + "_pattern"),
            severity=severity,
            confidence=0.95,
            source_node=self.node_id,
            timestamp=_dt.datetime.utcnow().isoformat(),
        )
        self.add_signature(sig)
        block = self.mine_block(force=True)
        if block is None:
            block = self._flush_pending()
        return block
