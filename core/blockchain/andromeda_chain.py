#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Andromeda Chain
Blockchain légère pour le partage décentralisé de signatures de menaces.
"""

import hashlib
import json
import time
import logging
import threading
import socket
import random
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import pickle
import base64

logger = logging.getLogger(__name__)

@dataclass
class ThreatSignature:
    """Signature de menace pour la blockchain."""
    signature_id: str
    threat_type: str
    hash_sha256: str
    pattern: str
    severity: str
    confidence: float
    source_node: str
    timestamp: datetime
    metadata: Dict[str, Any]

@dataclass
class Block:
    """Bloc de la blockchain Andromeda."""
    index: int
    timestamp: datetime
    signatures: List[ThreatSignature]
    previous_hash: str
    nonce: int
    hash: str
    node_id: str

@dataclass
class Node:
    """Nœud du réseau Andromeda Chain."""
    node_id: str
    ip_address: str
    port: int
    public_key: str
    reputation: float
    last_seen: datetime
    is_decoy: bool = False

class AndromedaChain:
    """
    Blockchain légère Andromeda Chain pour partage de signatures de menaces.
    Implémente un consensus léger adapté aux appareils IoT.
    """
    
    def __init__(self, node_id: str = None, port: int = 9050):
        """
        Initialise la blockchain Andromeda Chain.
        
        Args:
            node_id: Identifiant unique du nœud
            port: Port d'écoute du nœud
        """
        self.node_id = node_id or self._generate_node_id()
        self.port = port
        self.status = "initializing"
        
        # Configuration
        self.config = {
            "max_block_size": 100,  # Nombre max de signatures par bloc
            "block_time": 60,       # Temps cible entre blocs (secondes)
            "consensus_threshold": 0.51,  # Seuil de consensus
            "max_peers": 50,        # Nombre max de pairs
            "decoy_node_ratio": 0.1,  # 10% de nœuds leurres
            "signature_ttl": 7 * 24 * 3600,  # TTL des signatures (7 jours)
        }
        
        # État de la blockchain
        self.chain: List[Block] = []
        self.pending_signatures: List[ThreatSignature] = []
        self.signature_pool: Dict[str, ThreatSignature] = {}
        
        # Réseau P2P
        self.peers: Dict[str, Node] = {}
        self.is_decoy_node = False
        self.network_active = False
        
        # Threading
        self.mining_active = False
        self.sync_active = False
        self.mining_thread = None
        self.sync_thread = None
        self.network_thread = None
        
        # Initialisation
        self._create_genesis_block()
        self._setup_networking()
        
        self.status = "operational"
        logger.info(f"Andromeda Chain initialisé - Node: {self.node_id}")
    
    def _generate_node_id(self) -> str:
        """Génère un identifiant unique pour le nœud."""
        timestamp = str(int(time.time()))
        random_part = str(random.randint(10000, 99999))
        raw_id = f"node_{timestamp}_{random_part}"
        return hashlib.sha256(raw_id.encode()).hexdigest()[:16]
    
    def _create_genesis_block(self):
        """Crée le bloc genesis."""
        genesis_signatures = [
            ThreatSignature(
                signature_id="genesis_sig",
                threat_type="system",
                hash_sha256="0" * 64,
                pattern="genesis",
                severity="info",
                confidence=1.0,
                source_node=self.node_id,
                timestamp=datetime.now(),
                metadata={"type": "genesis"}
            )
        ]
        
        genesis_block = Block(
            index=0,
            timestamp=datetime.now(),
            signatures=genesis_signatures,
            previous_hash="0" * 64,
            nonce=0,
            hash="",
            node_id=self.node_id
        )
        
        genesis_block.hash = self._calculate_block_hash(genesis_block)
        self.chain.append(genesis_block)
        
        logger.info("Bloc genesis créé")
    
    def _setup_networking(self):
        """Configure le réseau P2P."""
        try:
            # Détermination si ce nœud doit être un leurre
            if random.random() < self.config["decoy_node_ratio"]:
                self.is_decoy_node = True
                logger.info("Nœud configuré en mode leurre")
            
            # Démarrage du serveur réseau
            self.network_thread = threading.Thread(target=self._network_server, daemon=True)
            self.network_thread.start()
            
            # Démarrage de la synchronisation
            self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
            self.sync_thread.start()
            
            self.network_active = True
            logger.info(f"Réseau P2P démarré sur le port {self.port}")
            
        except Exception as e:
            logger.error(f"Erreur configuration réseau: {e}")
            self.network_active = False
    
    def add_threat_signature(self, signature_data: Dict) -> str:
        """
        Ajoute une signature de menace à la blockchain.
        
        Args:
            signature_data: Données de la signature
            
        Returns:
            Hash du bloc créé
        """
        try:
            # Créer un objet ThreatSignature à partir des données
            signature = ThreatSignature(
                signature_id=signature_data.get("signature_id", f"sig_{int(time.time())}"),
                threat_type=signature_data.get("threat_type", "unknown"),
                hash_sha256=signature_data.get("hash", "0" * 64),
                pattern=signature_data.get("pattern", ""),
                severity=signature_data.get("severity", "medium"),
                confidence=signature_data.get("confidence", 0.5),
                source_node=self.node_id,
                timestamp=datetime.now(),
                metadata=signature_data.get("metadata", {})
            )
            
            # Ajouter à la blockchain
            success = self._add_signature_to_chain(signature)
            
            if success and self.chain:
                return self.chain[-1].hash
            else:
                return "error"
                
        except Exception as e:
            logger.error(f"Erreur ajout signature: {e}")
            return "error"
    
    def _add_signature_to_chain(self, signature: ThreatSignature) -> bool:
        """Ajoute une signature à la blockchain."""
        try:
            # Validation de la signature
            if not self._validate_signature(signature):
                logger.error(f"Signature invalide: {signature.signature_id}")
                return False
            
            # Vérification des doublons
            if signature.signature_id in self.signature_pool:
                logger.debug(f"Signature déjà présente: {signature.signature_id}")
                return False
            
            # Ajout au pool et aux signatures en attente
            self.signature_pool[signature.signature_id] = signature
            self.pending_signatures.append(signature)
            
            # Propagation aux pairs
            self._propagate_signature(signature)
            
            logger.info(f"Signature ajoutée: {signature.signature_id}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur ajout signature à la chaîne: {e}")
            return False
    
    def _validate_signature(self, signature: ThreatSignature) -> bool:
        """Valide une signature de menace."""
        # Vérification des champs obligatoires
        if not all([signature.signature_id, signature.threat_type, 
                   signature.hash_sha256, signature.pattern]):
            return False
        
        # Vérification du hash SHA256
        if len(signature.hash_sha256) != 64:
            return False
        
        # Vérification de la sévérité
        if signature.severity not in ["critical", "high", "medium", "low", "info"]:
            return False
        
        # Vérification de la confiance
        if not 0.0 <= signature.confidence <= 1.0:
            return False
        
        return True
    
    def _propagate_signature(self, signature: ThreatSignature):
        """Propage une signature aux nœuds pairs."""
        try:
            signature_data = {
                "type": "new_signature",
                "signature": asdict(signature),
                "node_id": self.node_id,
                "timestamp": datetime.now().isoformat()
            }
            
            # Envoi aux pairs connectés
            for peer_id, peer in self.peers.items():
                try:
                    self._send_to_peer(peer, signature_data)
                except Exception as e:
                    logger.warning(f"Erreur envoi à peer {peer_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Erreur propagation signature: {e}")
    
    def start_mining(self):
        """Démarre le minage de blocs."""
        if not self.mining_active:
            self.mining_active = True
            self.mining_thread = threading.Thread(target=self._mining_loop, daemon=True)
            self.mining_thread.start()
            logger.info("Minage démarré")
    
    def stop_mining(self):
        """Arrête le minage de blocs."""
        self.mining_active = False
        if self.mining_thread and self.mining_thread.is_alive():
            self.mining_thread.join(timeout=5)
        logger.info("Minage arrêté")
    
    def _mining_loop(self):
        """Boucle principale de minage."""
        while self.mining_active:
            try:
                # Attente d'avoir assez de signatures ou du timeout
                if (len(self.pending_signatures) >= self.config["max_block_size"] or
                    self._should_mine_block()):
                    
                    # Création d'un nouveau bloc
                    new_block = self._create_new_block()
                    
                    if new_block:
                        # Validation et ajout à la chaîne
                        if self._validate_block(new_block):
                            self.chain.append(new_block)
                            self._clear_mined_signatures(new_block)
                            
                            # Propagation du bloc
                            self._propagate_block(new_block)
                            
                            logger.info(f"Nouveau bloc miné: {new_block.index}")
                        else:
                            logger.error("Bloc miné invalide")
                
                time.sleep(5)  # Vérification toutes les 5 secondes
                
            except Exception as e:
                logger.error(f"Erreur boucle minage: {e}")
                time.sleep(10)
    
    def _should_mine_block(self) -> bool:
        """Détermine s'il faut miner un bloc maintenant."""
        if not self.pending_signatures:
            return False
        
        last_block = self.chain[-1]
        time_since_last = (datetime.now() - last_block.timestamp).total_seconds()
        
        return time_since_last >= self.config["block_time"]
    
    def _create_new_block(self) -> Optional[Block]:
        """Crée un nouveau bloc avec les signatures en attente."""
        try:
            if not self.pending_signatures:
                return None
            
            # Sélection des signatures pour le bloc
            signatures_for_block = self.pending_signatures[:self.config["max_block_size"]]
            
            # Création du bloc
            new_block = Block(
                index=len(self.chain),
                timestamp=datetime.now(),
                signatures=signatures_for_block,
                previous_hash=self.chain[-1].hash,
                nonce=0,
                hash="",
                node_id=self.node_id
            )
            
            # Calcul du hash (mining léger)
            new_block.hash = self._mine_block(new_block)
            
            return new_block
            
        except Exception as e:
            logger.error(f"Erreur création bloc: {e}")
            return None
    
    def _mine_block(self, block: Block) -> str:
        """Mine un bloc (proof of work léger)."""
        # Pour Andromeda Chain, on utilise un PoW très léger
        # adapté aux appareils à faible puissance
        target_difficulty = 1  # Très facile pour les appareils IoT
        
        while True:
            block_hash = self._calculate_block_hash(block)
            
            # Vérification de la difficulté (nombre de zéros au début)
            if block_hash[:target_difficulty] == "0" * target_difficulty:
                return block_hash
            
            block.nonce += 1
            
            # Limitation pour éviter le blocage sur appareils faibles
            if block.nonce > 100000:
                break
        
        # Fallback: retourner le hash même sans atteindre la difficulté
        return self._calculate_block_hash(block)
    
    def _calculate_block_hash(self, block: Block) -> str:
        """Calcule le hash d'un bloc."""
        # Préparation des données pour le hachage
        signatures_data = []
        for sig in block.signatures:
            sig_dict = asdict(sig)
            sig_dict['timestamp'] = sig_dict['timestamp'].isoformat()
            signatures_data.append(sig_dict)
        
        block_data = {
            "index": block.index,
            "timestamp": block.timestamp.isoformat(),
            "signatures": signatures_data,
            "previous_hash": block.previous_hash,
            "nonce": block.nonce,
            "node_id": block.node_id
        }
        
        block_string = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def _validate_block(self, block: Block) -> bool:
        """Valide un bloc."""
        try:
            # Vérification de l'index
            if block.index != len(self.chain):
                return False
            
            # Vérification du hash précédent
            if block.previous_hash != self.chain[-1].hash:
                return False
            
            # Vérification du hash du bloc
            calculated_hash = self._calculate_block_hash(block)
            if block.hash != calculated_hash:
                return False
            
            # Validation des signatures
            for signature in block.signatures:
                if not self._validate_signature(signature):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur validation bloc: {e}")
            return False
    
    def _clear_mined_signatures(self, block: Block):
        """Supprime les signatures minées du pool en attente."""
        mined_ids = {sig.signature_id for sig in block.signatures}
        self.pending_signatures = [
            sig for sig in self.pending_signatures
            if sig.signature_id not in mined_ids
        ]
    
    def _propagate_block(self, block: Block):
        """Propage un bloc aux nœuds pairs."""
        try:
            # Sérialisation du bloc pour transmission
            block_data = asdict(block)
            block_data['timestamp'] = block_data['timestamp'].isoformat()
            
            for sig_data in block_data['signatures']:
                sig_data['timestamp'] = sig_data['timestamp'].isoformat()
            
            message = {
                "type": "new_block",
                "block": block_data,
                "node_id": self.node_id
            }
            
            # Envoi aux pairs
            for peer_id, peer in self.peers.items():
                try:
                    self._send_to_peer(peer, message)
                except Exception as e:
                    logger.warning(f"Erreur envoi bloc à peer {peer_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Erreur propagation bloc: {e}")
    
    def _network_server(self):
        """Serveur réseau pour écouter les connexions P2P."""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.port))
            server_socket.listen(10)
            
            logger.info(f"Serveur P2P en écoute sur le port {self.port}")
            
            while self.network_active:
                try:
                    client_socket, addr = server_socket.accept()
                    # Traitement de la connexion dans un thread séparé
                    client_thread = threading.Thread(
                        target=self._handle_peer_connection,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.network_active:
                        logger.error(f"Erreur serveur réseau: {e}")
                        time.sleep(1)
            
            server_socket.close()
            
        except Exception as e:
            logger.error(f"Erreur critique serveur réseau: {e}")
    
    def _handle_peer_connection(self, client_socket, addr):
        """Gère une connexion avec un pair."""
        try:
            # Réception du message
            data = client_socket.recv(4096)
            if data:
                message = json.loads(data.decode())
                self._process_peer_message(message, addr)
            
        except Exception as e:
            logger.error(f"Erreur traitement connexion peer {addr}: {e}")
        finally:
            client_socket.close()
    
    def _process_peer_message(self, message: Dict, sender_addr):
        """Traite un message reçu d'un pair."""
        try:
            msg_type = message.get("type")
            
            if msg_type == "new_signature":
                self._handle_new_signature(message)
            elif msg_type == "new_block":
                self._handle_new_block(message)
            elif msg_type == "peer_discovery":
                self._handle_peer_discovery(message, sender_addr)
            elif msg_type == "sync_request":
                self._handle_sync_request(message, sender_addr)
            else:
                logger.warning(f"Type de message inconnu: {msg_type}")
                
        except Exception as e:
            logger.error(f"Erreur traitement message peer: {e}")
    
    def _handle_new_signature(self, message: Dict):
        """Traite une nouvelle signature reçue."""
        try:
            sig_data = message["signature"]
            
            # Reconstitution de la signature
            signature = ThreatSignature(
                signature_id=sig_data["signature_id"],
                threat_type=sig_data["threat_type"],
                hash_sha256=sig_data["hash_sha256"],
                pattern=sig_data["pattern"],
                severity=sig_data["severity"],
                confidence=sig_data["confidence"],
                source_node=sig_data["source_node"],
                timestamp=datetime.fromisoformat(sig_data["timestamp"]),
                metadata=sig_data["metadata"]
            )
            
            # Ajout si valide et nouveau
            if signature.signature_id not in self.signature_pool:
                self.add_threat_signature(signature)
                
        except Exception as e:
            logger.error(f"Erreur traitement nouvelle signature: {e}")
    
    def _handle_new_block(self, message: Dict):
        """Traite un nouveau bloc reçu."""
        try:
            block_data = message["block"]
            
            # Reconstitution du bloc
            signatures = []
            for sig_data in block_data["signatures"]:
                sig = ThreatSignature(
                    signature_id=sig_data["signature_id"],
                    threat_type=sig_data["threat_type"],
                    hash_sha256=sig_data["hash_sha256"],
                    pattern=sig_data["pattern"],
                    severity=sig_data["severity"],
                    confidence=sig_data["confidence"],
                    source_node=sig_data["source_node"],
                    timestamp=datetime.fromisoformat(sig_data["timestamp"]),
                    metadata=sig_data["metadata"]
                )
                signatures.append(sig)
            
            block = Block(
                index=block_data["index"],
                timestamp=datetime.fromisoformat(block_data["timestamp"]),
                signatures=signatures,
                previous_hash=block_data["previous_hash"],
                nonce=block_data["nonce"],
                hash=block_data["hash"],
                node_id=block_data["node_id"]
            )
            
            # Validation et ajout
            if block.index == len(self.chain) and self._validate_block(block):
                self.chain.append(block)
                self._clear_mined_signatures(block)
                logger.info(f"Bloc reçu et ajouté: {block.index}")
            
        except Exception as e:
            logger.error(f"Erreur traitement nouveau bloc: {e}")
    
    def _send_to_peer(self, peer: Node, message: Dict):
        """Envoie un message à un pair."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((peer.ip_address, peer.port))
                
                message_data = json.dumps(message)
                sock.send(message_data.encode())
                
        except Exception as e:
            logger.error(f"Erreur envoi à peer {peer.node_id}: {e}")
    
    def _sync_loop(self):
        """Boucle de synchronisation avec les pairs."""
        while self.sync_active:
            try:
                # Synchronisation périodique
                self._sync_with_peers()
                
                # Nettoyage des signatures expirées
                self._cleanup_expired_signatures()
                
                # Nettoyage des pairs inactifs
                self._cleanup_inactive_peers()
                
                time.sleep(30)  # Sync toutes les 30 secondes
                
            except Exception as e:
                logger.error(f"Erreur boucle sync: {e}")
                time.sleep(60)
    
    def _sync_with_peers(self):
        """Synchronise la blockchain avec les pairs."""
        # Implémentation basique - à améliorer
        logger.debug("Synchronisation avec les pairs")
    
    def _cleanup_expired_signatures(self):
        """Nettoie les signatures expirées."""
        try:
            current_time = datetime.now()
            ttl_threshold = current_time - timedelta(seconds=self.config["signature_ttl"])
            
            # Nettoyage du pool
            expired_sigs = [
                sig_id for sig_id, sig in self.signature_pool.items()
                if sig.timestamp < ttl_threshold
            ]
            
            for sig_id in expired_sigs:
                del self.signature_pool[sig_id]
            
            # Nettoyage des signatures en attente
            self.pending_signatures = [
                sig for sig in self.pending_signatures
                if sig.timestamp >= ttl_threshold
            ]
            
            if expired_sigs:
                logger.info(f"Nettoyé {len(expired_sigs)} signatures expirées")
                
        except Exception as e:
            logger.error(f"Erreur nettoyage signatures: {e}")
    
    def _cleanup_inactive_peers(self):
        """Nettoie les pairs inactifs."""
        try:
            current_time = datetime.now()
            inactive_threshold = current_time - timedelta(hours=1)
            
            inactive_peers = [
                peer_id for peer_id, peer in self.peers.items()
                if peer.last_seen < inactive_threshold
            ]
            
            for peer_id in inactive_peers:
                del self.peers[peer_id]
            
            if inactive_peers:
                logger.info(f"Supprimé {len(inactive_peers)} pairs inactifs")
                
        except Exception as e:
            logger.error(f"Erreur nettoyage pairs: {e}")
    
    def connect_to_bootstrap_nodes(self, bootstrap_nodes: List[str]):
        """Se connecte aux nœuds de bootstrap."""
        for node_address in bootstrap_nodes:
            try:
                host, port = node_address.split(':')
                port = int(port)
                
                # Tentative de connexion
                self._connect_to_peer(host, port)
                
            except Exception as e:
                logger.warning(f"Erreur connexion bootstrap {node_address}: {e}")
    
    def _connect_to_peer(self, host: str, port: int):
        """Se connecte à un pair spécifique."""
        try:
            # Message de découverte
            discovery_message = {
                "type": "peer_discovery",
                "node_id": self.node_id,
                "port": self.port,
                "timestamp": datetime.now().isoformat()
            }
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((host, port))
                
                message_data = json.dumps(discovery_message)
                sock.send(message_data.encode())
                
            logger.info(f"Connexion établie avec {host}:{port}")
            
        except Exception as e:
            logger.error(f"Erreur connexion peer {host}:{port}: {e}")
    
    def get_blockchain_info(self) -> Dict:
        """Retourne les informations de la blockchain."""
        return {
            "node_id": self.node_id,
            "chain_length": len(self.chain),
            "pending_signatures": len(self.pending_signatures),
            "total_signatures": len(self.signature_pool),
            "peers_count": len(self.peers),
            "is_mining": self.mining_active,
            "is_decoy_node": self.is_decoy_node,
            "last_block_hash": self.chain[-1].hash if self.chain else None,
            "last_block_time": self.chain[-1].timestamp.isoformat() if self.chain else None
        }
    
    def search_signatures(self, query: Dict) -> List[ThreatSignature]:
        """Recherche des signatures dans la blockchain."""
        results = []
        
        try:
            threat_type = query.get("threat_type")
            severity = query.get("severity")
            pattern = query.get("pattern")
            
            for signature in self.signature_pool.values():
                match = True
                
                if threat_type and signature.threat_type != threat_type:
                    match = False
                
                if severity and signature.severity != severity:
                    match = False
                
                if pattern and pattern.lower() not in signature.pattern.lower():
                    match = False
                
                if match:
                    results.append(signature)
            
            # Tri par confiance décroissante
            results.sort(key=lambda x: x.confidence, reverse=True)
            
        except Exception as e:
            logger.error(f"Erreur recherche signatures: {e}")
        
        return results
    
    def validate_chain(self) -> bool:
        """
        Valide l'intégrité de la blockchain.
        
        Returns:
            True si la blockchain est valide
        """
        try:
            if not self.chain:
                return True  # Chaîne vide est valide
            
            # Vérification du bloc genesis
            if len(self.chain) > 0:
                genesis = self.chain[0]
                if genesis.previous_hash != "0":
                    logger.error("Bloc genesis invalide")
                    return False
            
            # Vérification de chaque bloc
            for i in range(1, len(self.chain)):
                current_block = self.chain[i]
                previous_block = self.chain[i - 1]
                
                # Vérification du hash précédent
                if current_block.previous_hash != previous_block.hash:
                    logger.error(f"Hash précédent invalide au bloc {i}")
                    return False
                
                # Vérification de l'intégrité du hash
                expected_hash = self._calculate_block_hash(current_block)
                if current_block.hash != expected_hash:
                    logger.error(f"Hash du bloc {i} invalide")
                    return False
            
            logger.info("Blockchain validée avec succès")
            return True
            
        except Exception as e:
            logger.error(f"Erreur validation blockchain: {e}")
            return False
    
    def get_chain_stats(self) -> Dict:
        """Retourne les statistiques de la blockchain."""
        if not self.chain:
            return {"total_blocks": 0, "total_signatures": 0}
        
        total_blocks = len(self.chain)
        total_signatures = sum(len(block.signatures) for block in self.chain)
        
        return {"total_blocks": total_blocks, "total_signatures": total_signatures}
    
    def shutdown(self):
        """Arrête proprement la blockchain."""
        try:
            logger.info("Arrêt d'Andromeda Chain...")
            
            # Arrêt du minage
            self.stop_mining()
            
            # Arrêt du réseau
            self.network_active = False
            self.sync_active = False
            
            # Attente arrêt des threads
            if self.sync_thread and self.sync_thread.is_alive():
                self.sync_thread.join(timeout=5)
            
            if self.network_thread and self.network_thread.is_alive():
                self.network_thread.join(timeout=5)
            
            self.status = "shutdown"
            logger.info("Andromeda Chain arrêté")
            
        except Exception as e:
            logger.error(f"Erreur arrêt blockchain: {e}")
    
    def get_status(self) -> Dict:
        """Retourne le statut de la blockchain."""
        return {
            "status": self.status,
            "node_id": self.node_id,
            "chain_length": len(self.chain),
            "mining_active": self.mining_active,
            "network_active": self.network_active,
            "peers_count": len(self.peers)
        } 