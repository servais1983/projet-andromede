#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Astra Assistant
Assistant vocal IA pour l'interaction utilisateur naturelle.
"""

import logging
from typing import Dict, List, Optional, Any
import json
from datetime import datetime

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

class AstraAssistant:
    """
    Assistant IA conversationnel pour le projet Andromède.
    Mode dégradé disponible sans PyTorch.
    """
    
    def __init__(self, device=None):
        """
        Initialise l'assistant Astra.
        
        Args:
            device: Device PyTorch (ignoré en mode dégradé)
        """
        self.device = device or "cpu"
        self.degraded_mode = not TORCH_AVAILABLE
        
        # Historique des conversations
        self.sessions = {}
        
        # Réponses prédéfinies pour mode dégradé
        self.predefined_responses = {
            "bonjour": "Bonjour ! Je suis Astra, votre assistant de sécurité Andromède. Comment puis-je vous aider ?",
            "aide": "Je peux vous aider avec l'analyse de menaces, la compréhension des rapports de sécurité, et répondre à vos questions sur la cybersécurité.",
            "menace": "Pour analyser une menace, décrivez-moi ce que vous observez ou utilisez le scanner CSV intégré.",
            "rapport": "Les rapports d'Andromède contiennent des analyses détaillées des menaces détectées avec des recommandations de sécurité.",
            "aide_technique": "Pour une assistance technique approfondie, consultez la documentation ou contactez le support.",
            "statut": "Le système Andromède fonctionne en mode de base. Toutes les fonctionnalités essentielles sont opérationnelles."
        }
        
        # Statistiques
        self.stats = {
            "conversations": 0,
            "questions_answered": 0,
            "session_count": 0
        }
        
        if self.degraded_mode:
            logger.info("🤖 Astra Assistant initialisé (mode dégradé)")
        else:
            logger.info("🤖 Astra Assistant initialisé (mode complet)")

    def chat(self, message: str, session_id: str = "default") -> str:
        """
        Dialogue avec l'utilisateur.
        
        Args:
            message: Message de l'utilisateur
            session_id: Identifiant de session
            
        Returns:
            Réponse de l'assistant
        """
        try:
            # Initialiser la session si nécessaire
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    "history": [],
                    "created": datetime.now(),
                    "message_count": 0
                }
                self.stats["session_count"] += 1
            
            session = self.sessions[session_id]
            session["history"].append({"user": message, "timestamp": datetime.now()})
            session["message_count"] += 1
            
            # Traitement du message
            response = self._generate_response(message, session)
            
            # Enregistrer la réponse
            session["history"].append({"assistant": response, "timestamp": datetime.now()})
            
            # Mise à jour des statistiques
            self.stats["conversations"] += 1
            self.stats["questions_answered"] += 1
            
            return response
            
        except Exception as e:
            logger.error(f"Erreur chat Astra: {e}")
            return "Désolé, j'ai rencontré une erreur. Pouvez-vous reformuler votre question ?"

    def _generate_response(self, message: str, session: Dict) -> str:
        """Génère une réponse appropriée."""
        message_lower = message.lower().strip()
        
        # Réponses directes
        for keyword, response in self.predefined_responses.items():
            if keyword in message_lower:
                return response
        
        # Analyse contextuelle
        if any(word in message_lower for word in ["scanner", "csv", "analyser", "fichier"]):
            return """Pour utiliser le scanner CSV d'Andromède :
1. Accédez à l'interface web
2. Sélectionnez votre fichier CSV
3. Cliquez sur 'Analyser'
4. Consultez le rapport généré

Le scanner détecte automatiquement les menaces communes comme les injections SQL, XSS, malwares, etc."""

        if any(word in message_lower for word in ["sécurité", "protection", "menace", "cyberattaque"]):
            return """Andromède offre une protection multicouche :
- Analyse de menaces en temps réel
- Détection basée sur les patterns
- Rapports détaillés avec recommandations
- Interface intuitive pour tous les niveaux

Pour une menace spécifique, décrivez-moi ce que vous observez."""

        if any(word in message_lower for word in ["erreur", "problème", "bug", "ne fonctionne pas"]):
            return """Si vous rencontrez des problèmes :
1. Vérifiez que tous les fichiers requis sont présents
2. Consultez les logs pour plus de détails
3. Redémarrez l'application si nécessaire
4. Contactez le support technique si le problème persiste

Pouvez-vous me décrire plus précisément le problème rencontré ?"""

        if "?" in message_lower:
            return """Je suis là pour vous aider ! Vous pouvez me poser des questions sur :
- L'utilisation du scanner Andromède
- L'interprétation des rapports de sécurité
- Les menaces de cybersécurité
- Les fonctionnalités du système

Que souhaitez-vous savoir ?"""

        # Réponse par défaut
        return """Je comprends votre question. Voici comment je peux vous aider :

🔍 **Analyse de menaces** : "Analyse ce fichier suspect"
📊 **Rapports** : "Explique ce rapport de sécurité"
🛡️ **Sécurité** : "Comment me protéger contre les malwares ?"
❓ **Aide** : "Comment utiliser Andromède ?"

Que puis-je faire pour vous ?"""

    def get_session_history(self, session_id: str) -> List[Dict]:
        """Récupère l'historique d'une session."""
        if session_id in self.sessions:
            return self.sessions[session_id]["history"]
        return []

    def clear_session(self, session_id: str) -> bool:
        """Efface une session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques."""
        return {
            "mode": "degraded" if self.degraded_mode else "full",
            "active_sessions": len(self.sessions),
            "stats": self.stats.copy(),
            "torch_available": TORCH_AVAILABLE
        } 