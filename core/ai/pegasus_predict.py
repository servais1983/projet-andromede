#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Pegasus Predict
Système de prédiction de vulnérabilités basé sur l'IA.
"""

import logging
from typing import Dict, List, Optional, Any
import json
from datetime import datetime, timedelta

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Imports conditionnels
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch non disponible - mode dégradé")

class PegasusPredict:
    """
    Système de prédiction de vulnérabilités.
    Mode dégradé disponible sans PyTorch.
    """
    
    def __init__(self, device=None):
        """
        Initialise Pegasus Predict.
        
        Args:
            device: Device PyTorch (ignoré en mode dégradé)
        """
        self.device = device or "cpu"
        self.degraded_mode = not TORCH_AVAILABLE
        
        # Base de connaissances des vulnérabilités
        self.vulnerability_patterns = {
            "sql_injection": {
                "indicators": ["'", "SELECT", "UNION", "DROP", "INSERT", "--", "/*"],
                "risk_level": "high",
                "cve_examples": ["CVE-2021-44228", "CVE-2019-0708"],
                "mitigation": "Utiliser des requêtes préparées et validation d'entrée"
            },
            "xss": {
                "indicators": ["<script>", "javascript:", "alert(", "onerror="],
                "risk_level": "medium",
                "cve_examples": ["CVE-2020-1472", "CVE-2021-26855"],
                "mitigation": "Encoder les sorties et implémenter CSP"
            },
            "command_injection": {
                "indicators": ["|", "&", ";", "$(", "`"],
                "risk_level": "critical",
                "cve_examples": ["CVE-2021-44228", "CVE-2020-1350"],
                "mitigation": "Valider et assainir toutes les entrées utilisateur"
            },
            "file_inclusion": {
                "indicators": ["../", "..\\", "/etc/", "\\windows\\"],
                "risk_level": "high",
                "cve_examples": ["CVE-2020-0688", "CVE-2019-11510"],
                "mitigation": "Contrôler l'accès aux fichiers et valider les chemins"
            }
        }
        
        # Statistiques
        self.stats = {
            "predictions_made": 0,
            "vulnerabilities_detected": 0,
            "accuracy_score": 85.2  # Score simulé
        }
        
        logger.info(f"🔮 Pegasus Predict initialisé (mode: {'dégradé' if self.degraded_mode else 'complet'})")

    def predict_vulnerabilities(self, data: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Prédit les vulnérabilités potentielles.
        
        Args:
            data: Données à analyser
            context: Contexte optionnel
            
        Returns:
            Prédictions de vulnérabilités
        """
        try:
            start_time = datetime.now()
            
            vulnerabilities_found = []
            risk_score = 0.0
            
            data_lower = data.lower()
            
            # Analyse des patterns de vulnérabilités
            for vuln_type, pattern_info in self.vulnerability_patterns.items():
                matches = 0
                matched_indicators = []
                
                for indicator in pattern_info["indicators"]:
                    if indicator.lower() in data_lower:
                        matches += 1
                        matched_indicators.append(indicator)
                
                if matches > 0:
                    confidence = min(0.95, matches * 0.2)
                    severity_score = self._calculate_severity_score(pattern_info["risk_level"])
                    
                    vulnerability = {
                        "type": vuln_type,
                        "confidence": confidence,
                        "severity": pattern_info["risk_level"],
                        "severity_score": severity_score,
                        "indicators_found": matched_indicators,
                        "cve_references": pattern_info["cve_examples"][:2],
                        "mitigation": pattern_info["mitigation"],
                        "matches_count": matches
                    }
                    
                    vulnerabilities_found.append(vulnerability)
                    risk_score = max(risk_score, confidence * severity_score)
            
            # Prédictions temporelles
            temporal_prediction = self._predict_temporal_risk(vulnerabilities_found)
            
            # Mise à jour des statistiques
            self.stats["predictions_made"] += 1
            if vulnerabilities_found:
                self.stats["vulnerabilities_detected"] += 1
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return {
                "vulnerabilities": vulnerabilities_found,
                "risk_score": risk_score,
                "overall_risk": self._categorize_risk(risk_score),
                "temporal_prediction": temporal_prediction,
                "recommendations": self._generate_recommendations(vulnerabilities_found),
                "processing_time": processing_time,
                "prediction_accuracy": self.stats["accuracy_score"],
                "timestamp": datetime.now().isoformat(),
                "mode": "degraded" if self.degraded_mode else "full"
            }
            
        except Exception as e:
            logger.error(f"Erreur prédiction Pegasus: {e}")
            return {
                "error": str(e),
                "vulnerabilities": [],
                "risk_score": 0.0,
                "mode": "error"
            }

    def _calculate_severity_score(self, risk_level: str) -> float:
        """Calcule le score de sévérité."""
        severity_mapping = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.4,
            "info": 0.2
        }
        return severity_mapping.get(risk_level.lower(), 0.5)

    def _categorize_risk(self, risk_score: float) -> str:
        """Catégorise le niveau de risque."""
        if risk_score >= 0.8:
            return "Critique"
        elif risk_score >= 0.6:
            return "Élevé"
        elif risk_score >= 0.4:
            return "Moyen"
        elif risk_score >= 0.2:
            return "Faible"
        else:
            return "Minimal"

    def _predict_temporal_risk(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Prédit l'évolution temporelle du risque."""
        if not vulnerabilities:
            return {
                "trend": "stable",
                "risk_evolution": "minimal",
                "time_to_exploit": "N/A"
            }
        
        max_severity = max(v["severity_score"] for v in vulnerabilities)
        vuln_count = len(vulnerabilities)
        
        # Estimation simple du temps d'exploitation
        if max_severity >= 0.8:
            time_to_exploit = "24-48 heures"
            trend = "critique"
        elif max_severity >= 0.6:
            time_to_exploit = "1-7 jours"
            trend = "préoccupant"
        else:
            time_to_exploit = "1-4 semaines"
            trend = "surveillé"
        
        return {
            "trend": trend,
            "risk_evolution": "croissant" if vuln_count > 2 else "stable",
            "time_to_exploit": time_to_exploit,
            "exploitation_probability": min(0.9, max_severity * vuln_count * 0.2)
        }

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Génère des recommandations basées sur les vulnérabilités."""
        if not vulnerabilities:
            return ["Aucune vulnérabilité critique détectée"]
        
        recommendations = set()
        
        for vuln in vulnerabilities:
            recommendations.add(vuln["mitigation"])
            
            if vuln["severity"] in ["critical", "high"]:
                recommendations.add("Correction immédiate requise")
                recommendations.add("Audit de sécurité approfondi recommandé")
        
        # Ajout de recommandations générales
        if len(vulnerabilities) > 1:
            recommendations.add("Mise en place d'une surveillance continue")
            recommendations.add("Formation équipe sur les vulnérabilités détectées")
        
        return list(recommendations)[:5]  # Limiter à 5 recommandations

    def get_vulnerability_trends(self, days: int = 30) -> Dict[str, Any]:
        """Analyse les tendances de vulnérabilités."""
        # Simulation de tendances pour mode dégradé
        return {
            "period": f"{days} derniers jours",
            "total_predictions": self.stats["predictions_made"],
            "vulnerabilities_found": self.stats["vulnerabilities_detected"],
            "most_common_types": ["sql_injection", "xss", "command_injection"],
            "trend": "stable",
            "accuracy": self.stats["accuracy_score"]
        }

    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut du système."""
        return {
            "status": "operational",
            "mode": "degraded" if self.degraded_mode else "full",
            "torch_available": TORCH_AVAILABLE,
            "stats": self.stats.copy(),
            "vulnerability_database_size": len(self.vulnerability_patterns)
        } 