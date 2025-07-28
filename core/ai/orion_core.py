#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Orion Core
Cœur d'intelligence artificielle principal utilisant Phi-3 pour l'analyse de sécurité.
"""

import os
import json
import logging
import hashlib
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import threading
import queue
import time

# Configuration du logging en premier
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Imports conditionnels avec gestion d'erreur
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logger.warning("NumPy non disponible - fonctionnalités limitées")

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch non disponible - mode dégradé")

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("Transformers non disponible - analyse basique")

class OrionCore:
    """
    Cœur d'intelligence artificielle principal du système Andromède.
    Utilise Phi-3 et d'autres modèles pour l'analyse de sécurité avancée.
    
    Mode dégradé disponible sans PyTorch pour fonctionnement basique.
    """
    
    def __init__(self, config_path: Optional[str] = None, device: Optional[str] = None):
        """
        Initialise le cœur IA Orion.
        
        Args:
            config_path: Chemin vers le fichier de configuration
            device: Device PyTorch ('cpu', 'cuda') - None pour auto-détection
        """
        self.config = self._load_config(config_path)
        self.status = "initializing"
        
        # Mode dégradé si PyTorch non disponible
        self.degraded_mode = not TORCH_AVAILABLE
        
        if self.degraded_mode:
            logger.info("🔄 Démarrage en mode dégradé (sans IA avancée)")
            self.device = "cpu"
            self.model = None
            self.tokenizer = None
            self.pipeline = None
        else:
            # Configuration PyTorch
            self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
            self.model = None
            self.tokenizer = None
            self.pipeline = None
        
        # Composants toujours disponibles
        self.threat_database = {}
        self.analysis_cache = {}
        self.session_history = {}
        
        # Statistiques
        self.stats = {
            "analyses_performed": 0,
            "threats_detected": 0,
            "false_positives": 0,
            "processing_time": []
        }
        
        self.status = "ready"
        logger.info(f"✅ Orion Core initialisé (mode: {'dégradé' if self.degraded_mode else 'complet'})")

    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        """Charge la configuration."""
        default_config = {
            "model_name": "microsoft/Phi-3-mini-4k-instruct",
            "max_tokens": 512,
            "temperature": 0.1,
            "analysis_timeout": 30,
            "cache_enabled": True,
            "threat_threshold": 0.7
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Erreur chargement config: {e}")
        
        return default_config

    def analyze_threat(self, data: str, context: str = "") -> Dict[str, Any]:
        """
        Analyse une menace potentielle.
        
        Args:
            data: Données à analyser
            context: Contexte additionnel
            
        Returns:
            Dict avec résultats d'analyse
        """
        start_time = time.time()
        
        try:
            if self.degraded_mode:
                # Analyse basique sans IA
                result = self._basic_threat_analysis(data, context)
            else:
                # Analyse IA complète
                result = self._ai_threat_analysis(data, context)
            
            # Mise à jour des statistiques
            processing_time = time.time() - start_time
            self.stats["analyses_performed"] += 1
            self.stats["processing_time"].append(processing_time)
            
            if result.get("is_threat", False):
                self.stats["threats_detected"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur analyse menace: {e}")
            return {
                "is_threat": False,
                "confidence": 0.0,
                "threat_type": "unknown",
                "description": f"Erreur d'analyse: {e}",
                "recommendations": ["Vérification manuelle requise"],
                "processing_time": time.time() - start_time,
                "mode": "error"
            }

    def _basic_threat_analysis(self, data: str, context: str = "") -> Dict[str, Any]:
        """Analyse basique sans IA pour mode dégradé."""
        # Patterns de menaces communes
        threat_patterns = {
            "sql_injection": ["'", "DROP", "SELECT", "UNION", "INSERT", "DELETE", "--", "/*"],
            "xss": ["<script>", "javascript:", "alert(", "onerror=", "onload="],
            "command_injection": ["&&", "||", "|", ";", "$(", "`"],
            "path_traversal": ["../", "..\\", "/etc/passwd", "\\windows\\"],
            "malware": [".exe", "trojan", "virus", "malware", "backdoor"],
            "credential_theft": ["password", "admin", "root", "login"],
            "network_attack": ["nmap", "scan", "bruteforce", "ddos"]
        }
        
        data_lower = data.lower()
        threats_found = []
        max_confidence = 0.0
        
        for threat_type, patterns in threat_patterns.items():
            pattern_matches = sum(1 for pattern in patterns if pattern.lower() in data_lower)
            if pattern_matches > 0:
                confidence = min(0.9, pattern_matches * 0.3)
                if confidence > max_confidence:
                    max_confidence = confidence
                threats_found.append({
                    "type": threat_type,
                    "confidence": confidence,
                    "matches": pattern_matches
                })
        
        is_threat = max_confidence >= self.config["threat_threshold"]
        
        return {
            "is_threat": is_threat,
            "confidence": max_confidence,
            "threat_type": threats_found[0]["type"] if threats_found else "none",
            "threats_found": threats_found,
            "description": f"Analyse basique: {'Menace détectée' if is_threat else 'Aucune menace évidente'}",
            "recommendations": self._get_recommendations(threats_found),
            "mode": "basic",
            "data_analyzed": len(data)
        }

    def _ai_threat_analysis(self, data: str, context: str = "") -> Dict[str, Any]:
        """Analyse IA complète (si PyTorch disponible)."""
        if not TORCH_AVAILABLE:
            return self._basic_threat_analysis(data, context)
        
        # TODO: Implémentation complète avec modèle Phi-3
        # Pour l'instant, utilise l'analyse basique améliorée
        basic_result = self._basic_threat_analysis(data, context)
        basic_result["mode"] = "ai_fallback"
        basic_result["description"] = "Analyse IA (mode fallback): " + basic_result["description"]
        
        return basic_result

    def _get_recommendations(self, threats_found: List[Dict]) -> List[str]:
        """Génère des recommandations basées sur les menaces trouvées."""
        if not threats_found:
            return ["Aucune action requise"]
        
        recommendations = []
        threat_types = [t["type"] for t in threats_found]
        
        if "sql_injection" in threat_types:
            recommendations.append("Vérifier et assainir les entrées utilisateur")
            recommendations.append("Utiliser des requêtes préparées")
        
        if "xss" in threat_types:
            recommendations.append("Encoder les sorties HTML")
            recommendations.append("Implémenter CSP (Content Security Policy)")
        
        if "malware" in threat_types:
            recommendations.append("Scanner avec antivirus à jour")
            recommendations.append("Isoler le fichier suspect")
        
        if "credential_theft" in threat_types:
            recommendations.append("Changer les mots de passe exposés")
            recommendations.append("Activer l'authentification 2FA")
        
        if "network_attack" in threat_types:
            recommendations.append("Vérifier les logs réseau")
            recommendations.append("Renforcer la configuration firewall")
        
        return recommendations[:3]  # Limiter à 3 recommandations

    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut du système."""
        return {
            "status": self.status,
            "mode": "degraded" if self.degraded_mode else "full",
            "device": self.device,
            "torch_available": TORCH_AVAILABLE,
            "transformers_available": TRANSFORMERS_AVAILABLE,
            "stats": self.stats.copy()
        } 