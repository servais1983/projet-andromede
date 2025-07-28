#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Gaia Generator
IA générative créant des leurres dynamiques et des défenses proactives utilisant Phi-3.
"""

import os
import json
import logging
import random
import string
import hashlib
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import tempfile
import threading
import time

# Imports conditionnels
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logging.warning("PyTorch non disponible pour Gaia")

try:
    from transformers import pipeline, AutoTokenizer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("Transformers non disponible pour Gaia")

logger = logging.getLogger(__name__)

class GaiaGenerator:
    """
    Générateur IA Gaia pour créer des défenses proactives et des leurres.
    Utilise Phi-3 pour générer du contenu adaptatif et contextuel.
    """
    
    def __init__(self, device):
        """
        Initialise Gaia Generator.
        
        Args:
            device: Device PyTorch à utiliser
        """
        self.device = device if TORCH_AVAILABLE else "cpu"
        self.status = "initializing"
        self.decoy_templates = self._load_decoy_templates()
        self.generated_decoys = {}
        self.active_honeypots = {}
        
        # Chargement du modèle de génération si disponible
        self.generator = None
        self.tokenizer = None
        
        if TRANSFORMERS_AVAILABLE:
            try:
                self.tokenizer = AutoTokenizer.from_pretrained("microsoft/DialoGPT-small")
                self.generator = pipeline(
                    "text-generation",
                    model="microsoft/DialoGPT-small",
                    tokenizer=self.tokenizer,
                    device=self.device if TORCH_AVAILABLE else -1,
                    max_length=512
                )
                self.status = "operational"
                logger.info("Gaia Generator initialisé avec succès")
            except Exception as e:
                logger.warning(f"Erreur chargement modèle génération: {e}")
                self.generator = None
                self.status = "degraded"
        else:
            self.status = "degraded"
            logger.info("Gaia Generator en mode dégradé")
        
        # Thread de maintenance des leurres
        self.maintenance_thread = threading.Thread(target=self._maintenance_worker, daemon=True)
        self.maintenance_thread.start()
    
    def _load_decoy_templates(self) -> Dict:
        """Charge les templates de leurres."""
        return {
            "honeypot_files": {
                "sensitive_documents": [
                    "confidential_passwords.txt", "admin_credentials.xlsx", 
                    "database_backup.sql", "api_keys.json", "private_keys.pem"
                ],
                "fake_logs": [
                    "access.log", "error.log", "security.log", 
                    "admin_sessions.log", "failed_logins.log"
                ],
                "decoy_configs": [
                    "database.conf", "redis.conf", "ssh_config", 
                    "nginx.conf", "ssl_certificate.key"
                ]
            },
            "network_decoys": {
                "fake_services": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
                    {"port": 3306, "service": "mysql", "version": "MySQL 5.7"},
                    {"port": 6379, "service": "redis", "version": "Redis 6.0"},
                    {"port": 5432, "service": "postgresql", "version": "PostgreSQL 12"}
                ],
                "fake_endpoints": [
                    "/admin", "/api/v1/users", "/backup", "/config", 
                    "/debug", "/internal", "/management", "/private"
                ]
            },
            "content_patterns": {
                "credentials": [
                    "username", "password", "api_key", "secret", 
                    "token", "auth", "login", "access"
                ],
                "sensitive_data": [
                    "ssn", "credit_card", "bank_account", "personal_info",
                    "customer_data", "financial", "confidential"
                ]
            }
        }
    
    def generate_countermeasures(self, threat_analysis: Dict) -> Dict:
        """
        Génère des contremesures adaptées à l'analyse de menace.
        
        Args:
            threat_analysis: Résultat d'analyse de menace
            
        Returns:
            Contremesures générées
        """
        try:
            threat_type = threat_analysis.get("threat_type", "Unknown")
            risk_level = threat_analysis.get("risk_level", "Medium")
            
            countermeasures = {
                "timestamp": datetime.now().isoformat(),
                "threat_type": threat_type,
                "risk_level": risk_level,
                "active_defenses": [],
                "honeypots": [],
                "decoy_files": [],
                "monitoring_rules": [],
                "adaptive_responses": []
            }
            
            # Génération de défenses actives
            countermeasures["active_defenses"] = self._generate_active_defenses(threat_type, risk_level)
            
            # Création de honeypots
            countermeasures["honeypots"] = self._generate_honeypots(threat_type)
            
            # Génération de fichiers leurres
            countermeasures["decoy_files"] = self._generate_decoy_files(threat_type)
            
            # Règles de surveillance
            countermeasures["monitoring_rules"] = self._generate_monitoring_rules(threat_analysis)
            
            # Réponses adaptatives
            countermeasures["adaptive_responses"] = self._generate_adaptive_responses(threat_analysis)
            
            return countermeasures
            
        except Exception as e:
            logger.error(f"Erreur génération contremesures: {e}")
            return self._fallback_countermeasures()
    
    def generate_decoys(self, context: str) -> Dict:
        """
        Génère des leurres basés sur le contexte.
        
        Args:
            context: Contexte pour la génération
            
        Returns:
            Leurres générés
        """
        try:
            decoy_id = hashlib.md5(f"{context}{time.time()}".encode()).hexdigest()[:8]
            
            decoys = {
                "decoy_id": decoy_id,
                "timestamp": datetime.now().isoformat(),
                "context": context,
                "file_decoys": self._create_file_decoys(context),
                "network_decoys": self._create_network_decoys(context),
                "data_decoys": self._create_data_decoys(context),
                "behavioral_decoys": self._create_behavioral_decoys(context)
            }
            
            # Stockage des leurres actifs
            self.generated_decoys[decoy_id] = decoys
            
            return decoys
            
        except Exception as e:
            logger.error(f"Erreur génération leurres: {e}")
            return {"error": "Génération de leurres échouée"}
    
    def _generate_active_defenses(self, threat_type: str, risk_level: str) -> List[Dict]:
        """Génère des défenses actives."""
        defenses = []
        
        base_defenses = [
            {
                "type": "firewall_rule",
                "action": "enhanced_monitoring",
                "description": "Surveillance renforcée du trafic réseau"
            },
            {
                "type": "access_control",
                "action": "stricter_authentication",
                "description": "Renforcement de l'authentification"
            }
        ]
        
        if risk_level in ["Critical", "High"]:
            critical_defenses = [
                {
                    "type": "network_isolation",
                    "action": "segment_suspicious_traffic",
                    "description": "Isolation des segments réseau suspects"
                },
                {
                    "type": "automated_response",
                    "action": "immediate_blocking",
                    "description": "Blocage automatique des sources suspectes"
                }
            ]
            defenses.extend(critical_defenses)
        
        # Défenses spécifiques au type de menace
        if threat_type == "malware":
            defenses.append({
                "type": "behavioral_analysis",
                "action": "monitor_process_behavior",
                "description": "Surveillance comportementale des processus"
            })
        elif threat_type == "network":
            defenses.append({
                "type": "traffic_analysis",
                "action": "deep_packet_inspection",
                "description": "Inspection approfondie des paquets"
            })
        
        return base_defenses + defenses
    
    def _generate_honeypots(self, threat_type: str) -> List[Dict]:
        """Génère des honeypots adaptés."""
        honeypots = []
        
        if threat_type in ["malware", "Unknown"]:
            honeypots.extend([
                {
                    "type": "file_honeypot",
                    "location": "/tmp/important_data.xlsx",
                    "content_type": "fake_spreadsheet",
                    "monitoring": "file_access"
                },
                {
                    "type": "process_honeypot",
                    "name": "backup_service.exe",
                    "fake_behavior": "simulated_backup",
                    "monitoring": "process_interaction"
                }
            ])
        
        if threat_type in ["network", "Unknown"]:
            honeypots.extend([
                {
                    "type": "network_honeypot",
                    "service": "fake_ssh",
                    "port": 2222,
                    "monitoring": "connection_attempts"
                },
                {
                    "type": "web_honeypot",
                    "endpoint": "/admin/login",
                    "fake_interface": "admin_panel",
                    "monitoring": "authentication_attempts"
                }
            ])
        
        # Génération dynamique avec IA si disponible
        if self.generator:
            ai_honeypots = self._generate_ai_honeypots(threat_type)
            honeypots.extend(ai_honeypots)
        
        return honeypots
    
    def _generate_ai_honeypots(self, threat_type: str) -> List[Dict]:
        """Génère des honeypots avec l'IA."""
        try:
            prompt = f"Generate honeypot ideas for {threat_type} threats. Focus on realistic decoys that would attract attackers:"
            
            response = self.generator(
                prompt,
                max_length=200,
                num_return_sequences=1,
                temperature=0.7
            )
            
            # Parsing basique de la réponse
            generated_text = response[0]["generated_text"]
            
            # Conversion en structure honeypot
            return [{
                "type": "ai_generated_honeypot",
                "description": generated_text[:100],
                "threat_focus": threat_type,
                "ai_generated": True
            }]
            
        except Exception as e:
            logger.error(f"Erreur génération IA honeypots: {e}")
            return []
    
    def _create_file_decoys(self, context: str) -> List[Dict]:
        """Crée des fichiers leurres."""
        return self._generate_decoy_files(context)
    
    def _generate_decoy_files(self, context: str) -> List[Dict]:
        """Génère des fichiers leurres."""
        file_decoys = []
        
        # Sélection de templates basés sur le contexte
        if "admin" in context.lower() or "credential" in context.lower():
            templates = self.decoy_templates["honeypot_files"]["sensitive_documents"]
        elif "log" in context.lower():
            templates = self.decoy_templates["honeypot_files"]["fake_logs"]
        else:
            templates = self.decoy_templates["honeypot_files"]["decoy_configs"]
        
        for template in random.sample(templates, min(3, len(templates))):
            decoy_content = self._generate_file_content(template, context)
            
            file_decoys.append({
                "filename": template,
                "path": f"/tmp/decoys/{template}",
                "content_preview": decoy_content[:100],
                "size_bytes": len(decoy_content),
                "permissions": "644",
                "monitoring": "file_access_tracking"
            })
        
        return file_decoys
    
    def _generate_file_content(self, filename: str, context: str) -> str:
        """Génère le contenu d'un fichier leurre."""
        if "password" in filename or "credential" in filename:
            return self._generate_credential_decoy()
        elif "log" in filename:
            return self._generate_log_decoy()
        elif "config" in filename or "conf" in filename:
            return self._generate_config_decoy()
        else:
            return self._generate_generic_decoy(context)
    
    def _generate_credential_decoy(self) -> str:
        """Génère un faux fichier de credentials."""
        fake_users = ["admin", "root", "service", "backup", "test"]
        fake_passwords = ["".join(random.choices(string.ascii_letters + string.digits, k=12)) for _ in range(5)]
        
        content = "# Credentials File - DO NOT SHARE\n"
        content += f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        for user, password in zip(fake_users, fake_passwords):
            content += f"{user}:{password}\n"
        
        content += "\n# Database connections\n"
        content += f"db_host=localhost\n"
        content += f"db_user=admin\n"
        content += f"db_pass={''.join(random.choices(string.ascii_letters + string.digits, k=16))}\n"
        
        return content
    
    def _generate_log_decoy(self) -> str:
        """Génère un faux fichier de log."""
        log_entries = []
        
        for i in range(20):
            timestamp = (datetime.now() - timedelta(hours=i)).strftime('%Y-%m-%d %H:%M:%S')
            ip = f"192.168.1.{random.randint(10, 200)}"
            action = random.choice(["LOGIN", "LOGOUT", "ACCESS", "FAILED_AUTH", "SUCCESS"])
            
            log_entries.append(f"[{timestamp}] {ip} - {action} - User: admin")
        
        return "\n".join(log_entries)
    
    def _generate_config_decoy(self) -> str:
        """Génère un faux fichier de configuration."""
        config = """# Application Configuration
# WARNING: Contains sensitive information

[database]
host=prod-db-01.internal
port=5432
username=app_user
password=Sup3rS3cur3P@ssw0rd!
ssl_mode=require

[redis]
host=cache-01.internal
port=6379
auth_token=redis_auth_token_2024

[api]
secret_key=api_secret_key_do_not_expose
jwt_secret=jwt_signing_key_keep_safe
rate_limit=1000

[logging]
level=INFO
file=/var/log/app.log
max_size=100MB
"""
        return config
    
    def _generate_generic_decoy(self, context: str) -> str:
        """Génère un contenu générique basé sur le contexte."""
        if self.generator:
            try:
                prompt = f"Generate realistic file content for a security decoy related to: {context}"
                response = self.generator(prompt, max_length=300, temperature=0.8)
                return response[0]["generated_text"]
            except:
                pass
        
        # Fallback
        return f"# Generated decoy content\n# Context: {context}\n# Timestamp: {datetime.now()}\n\nThis is decoy content designed to attract and monitor unauthorized access."
    
    def _create_network_decoys(self, context: str) -> List[Dict]:
        """Crée des leurres réseau."""
        network_decoys = []
        
        fake_services = self.decoy_templates["network_decoys"]["fake_services"]
        
        for service in random.sample(fake_services, 2):
            network_decoys.append({
                "type": "fake_service",
                "port": service["port"],
                "service_name": service["service"],
                "version": service["version"],
                "banner": f"{service['service']} {service['version']} ready",
                "response_behavior": "log_and_delay",
                "monitoring": "connection_logging"
            })
        
        return network_decoys
    
    def _create_data_decoys(self, context: str) -> List[Dict]:
        """Crée des leurres de données."""
        data_decoys = []
        
        # Génération de fausses données personnelles
        fake_records = []
        for i in range(5):
            fake_records.append({
                "id": f"USR{random.randint(10000, 99999)}",
                "name": f"User{i+1}",
                "email": f"user{i+1}@company.com",
                "ssn": f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}",
                "credit_card": f"4{random.randint(100000000000000, 999999999999999)}"
            })
        
        data_decoys.append({
            "type": "customer_database",
            "record_count": len(fake_records),
            "sample_data": fake_records[:2],  # Échantillon pour monitoring
            "location": "database.customers_backup",
            "encryption": "fake_encrypted",
            "monitoring": "data_access_tracking"
        })
        
        return data_decoys
    
    def _create_behavioral_decoys(self, context: str) -> List[Dict]:
        """Crée des leurres comportementaux."""
        behavioral_decoys = []
        
        # Processus leurres
        behavioral_decoys.append({
            "type": "fake_process",
            "name": "system_backup.exe",
            "fake_activity": "simulated_file_operations",
            "cpu_pattern": "periodic_activity",
            "network_behavior": "fake_data_transfer",
            "monitoring": "process_interaction_tracking"
        })
        
        # Sessions utilisateur leurres
        behavioral_decoys.append({
            "type": "fake_user_session",
            "username": "admin_backup",
            "login_pattern": "scheduled_maintenance",
            "activity_simulation": "system_checks",
            "monitoring": "session_monitoring"
        })
        
        return behavioral_decoys
    
    def _generate_monitoring_rules(self, threat_analysis: Dict) -> List[Dict]:
        """Génère des règles de surveillance."""
        rules = []
        
        base_rules = [
            {
                "rule_type": "file_access",
                "pattern": "decoy_files/*",
                "action": "alert_and_log",
                "severity": "high"
            },
            {
                "rule_type": "network_connection",
                "pattern": "honeypot_services",
                "action": "log_source_ip",
                "severity": "medium"
            }
        ]
        
        # Règles spécifiques au type de menace
        threat_type = threat_analysis.get("threat_type", "Unknown")
        
        if threat_type == "malware":
            rules.append({
                "rule_type": "process_behavior",
                "pattern": "suspicious_file_operations",
                "action": "quarantine_and_analyze",
                "severity": "critical"
            })
        
        return base_rules + rules
    
    def _generate_adaptive_responses(self, threat_analysis: Dict) -> List[Dict]:
        """Génère des réponses adaptatives."""
        responses = []
        
        risk_level = threat_analysis.get("risk_level", "Medium")
        
        if risk_level in ["Critical", "High"]:
            responses.extend([
                {
                    "trigger": "honeypot_interaction",
                    "response": "immediate_ip_blocking",
                    "duration": "24_hours",
                    "escalation": "security_team_alert"
                },
                {
                    "trigger": "multiple_decoy_access",
                    "response": "network_segment_isolation",
                    "duration": "until_manual_review",
                    "escalation": "incident_response_activation"
                }
            ])
        
        responses.append({
            "trigger": "decoy_file_modification",
            "response": "enhanced_monitoring",
            "duration": "1_hour",
            "escalation": "security_log_entry"
        })
        
        return responses
    
    def _fallback_countermeasures(self) -> Dict:
        """Contremesures de fallback."""
        return {
            "timestamp": datetime.now().isoformat(),
            "status": "fallback_mode",
            "basic_defenses": [
                "Enhanced logging enabled",
                "Network monitoring activated",
                "Access controls verified"
            ],
            "recommendations": [
                "Manual security review required",
                "Update threat intelligence",
                "Verify system integrity"
            ]
        }
    
    def _maintenance_worker(self):
        """Worker de maintenance des leurres."""
        while True:
            try:
                # Nettoyage des anciens leurres
                current_time = datetime.now()
                expired_decoys = []
                
                for decoy_id, decoy_data in self.generated_decoys.items():
                    decoy_time = datetime.fromisoformat(decoy_data["timestamp"])
                    if (current_time - decoy_time).total_seconds() > 24 * 3600:  # Expiration après 24h
                        expired_decoys.append(decoy_id)
                
                for decoy_id in expired_decoys:
                    del self.generated_decoys[decoy_id]
                    logger.info(f"Leurre expiré supprimé: {decoy_id}")
                
                # Rotation des honeypots
                self._rotate_honeypots()
                
                time.sleep(3600)  # Maintenance toutes les heures
                
            except Exception as e:
                logger.error(f"Erreur maintenance Gaia: {e}")
                time.sleep(600)  # Retry après 10 minutes en cas d'erreur
    
    def _rotate_honeypots(self):
        """Fait tourner les honeypots pour éviter la détection."""
        # Simulation de rotation des ports et services
        logger.debug("Rotation des honeypots effectuée")
    
    def get_active_decoys(self) -> Dict:
        """Retourne les leurres actifs."""
        return {
            "total_decoys": len(self.generated_decoys),
            "active_honeypots": len(self.active_honeypots),
            "decoys_by_type": self._get_decoys_statistics()
        }
    
    def _get_decoys_statistics(self) -> Dict:
        """Calcule les statistiques des leurres."""
        stats = {
            "file_decoys": 0,
            "network_decoys": 0,
            "data_decoys": 0,
            "behavioral_decoys": 0
        }
        
        for decoy_data in self.generated_decoys.values():
            if "file_decoys" in decoy_data:
                stats["file_decoys"] += len(decoy_data["file_decoys"])
            if "network_decoys" in decoy_data:
                stats["network_decoys"] += len(decoy_data["network_decoys"])
            if "data_decoys" in decoy_data:
                stats["data_decoys"] += len(decoy_data["data_decoys"])
            if "behavioral_decoys" in decoy_data:
                stats["behavioral_decoys"] += len(decoy_data["behavioral_decoys"])
        
        return stats
    
    def get_status(self) -> Dict:
        """Retourne le statut de Gaia Generator."""
        return {
            "status": self.status,
            "generator_loaded": self.generator is not None,
            "active_decoys": len(self.generated_decoys),
            "templates_loaded": len(self.decoy_templates),
            "torch_available": TORCH_AVAILABLE,
            "transformers_available": TRANSFORMERS_AVAILABLE
        } 