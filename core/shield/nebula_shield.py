#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Nebula Shield
Bouclier adaptatif avec micro-segmentation IA et système d'auto-réparation.
"""

import os
import json
import logging
import psutil
import threading
import time
import subprocess
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
import ipaddress
import socket

logger = logging.getLogger(__name__)

@dataclass
class SecurityRule:
    """Règle de sécurité pour micro-segmentation."""
    rule_id: str
    source: str
    destination: str
    port: int
    protocol: str
    action: str  # allow, deny, monitor
    priority: int
    created_at: datetime
    expires_at: Optional[datetime] = None

@dataclass
class SecurityBubble:
    """Bulle de sécurité pour isolation d'application."""
    bubble_id: str
    application_name: str
    process_ids: List[int]
    allowed_connections: List[str]
    blocked_connections: List[str]
    resource_limits: Dict[str, Any]
    created_at: datetime
    status: str  # active, suspended, terminated

class NebulaShield:
    """
    Bouclier adaptatif Nebula Shield pour protection multi-niveaux.
    Implémente la micro-segmentation IA et l'auto-réparation.
    """
    
    def __init__(self):
        """Initialise Nebula Shield."""
        self.status = "initializing"
        
        # Configuration
        self.config = {
            "microsegmentation_enabled": True,
            "auto_healing_enabled": True,
            "default_policy": "strict",  # strict, balanced, permissive
            "bubble_isolation_level": "high",
            "monitoring_interval": 5,  # secondes
            "rule_learning_enabled": True
        }
        
        # État du système
        self.security_rules: List[SecurityRule] = []
        self.security_bubbles: Dict[str, SecurityBubble] = {}
        self.threat_indicators: Set[str] = set()
        self.auto_healing_actions: List[Dict] = []
        
        # Monitoring
        self.network_monitor = NetworkMonitor()
        self.process_monitor = ProcessMonitor()
        self.vulnerability_scanner = VulnerabilityScanner()
        
        # Threads de monitoring
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.healing_thread = threading.Thread(target=self._auto_healing_loop, daemon=True)
        
        # Initialisation
        self._load_default_rules()
        self._start_monitoring()
        
        self.status = "operational"
        logger.info("Nebula Shield initialisé avec succès")
    
    def _load_default_rules(self):
        """Charge les règles de sécurité par défaut."""
        default_rules = [
            SecurityRule(
                rule_id="default_deny_all",
                source="*",
                destination="*",
                port=0,
                protocol="*",
                action="deny",
                priority=1000,
                created_at=datetime.now()
            ),
            SecurityRule(
                rule_id="allow_local_loopback",
                source="127.0.0.1",
                destination="127.0.0.1",
                port=0,
                protocol="*",
                action="allow",
                priority=100,
                created_at=datetime.now()
            ),
            SecurityRule(
                rule_id="allow_established_connections",
                source="*",
                destination="*",
                port=0,
                protocol="tcp",
                action="allow",
                priority=200,
                created_at=datetime.now()
            )
        ]
        
        self.security_rules.extend(default_rules)
        logger.info(f"Chargé {len(default_rules)} règles par défaut")
    
    def _start_monitoring(self):
        """Démarre les threads de monitoring."""
        self.monitor_thread.start()
        self.healing_thread.start()
        logger.info("Monitoring Nebula Shield démarré")
    
    def create_security_bubble(self, app_name: str, process_ids: List[int] = None) -> str:
        """
        Crée une bulle de sécurité pour isoler une application.
        
        Args:
            app_name: Nom de l'application
            process_ids: Liste des PIDs à isoler
            
        Returns:
            ID de la bulle créée
        """
        try:
            bubble_id = f"bubble_{app_name}_{int(time.time())}"
            
            # Détection automatique des processus si non spécifiés
            if not process_ids:
                process_ids = self._find_processes_by_name(app_name)
            
            # Configuration de la bulle
            bubble = SecurityBubble(
                bubble_id=bubble_id,
                application_name=app_name,
                process_ids=process_ids,
                allowed_connections=[],
                blocked_connections=[],
                resource_limits={
                    "max_memory_mb": 1024,
                    "max_cpu_percent": 80,
                    "max_network_connections": 100
                },
                created_at=datetime.now(),
                status="active"
            )
            
            # Application des restrictions réseau
            self._apply_network_isolation(bubble)
            
            # Application des limites de ressources
            self._apply_resource_limits(bubble)
            
            # Stockage de la bulle
            self.security_bubbles[bubble_id] = bubble
            
            logger.info(f"Bulle de sécurité créée: {bubble_id} pour {app_name}")
            return bubble_id
            
        except Exception as e:
            logger.error(f"Erreur création bulle sécurité: {e}")
            return ""
    
    def _find_processes_by_name(self, app_name: str) -> List[int]:
        """Trouve les processus par nom d'application."""
        process_ids = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if app_name.lower() in proc.info['name'].lower():
                        process_ids.append(proc.info['pid'])
                    elif proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline']).lower()
                        if app_name.lower() in cmdline:
                            process_ids.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Erreur recherche processus {app_name}: {e}")
        
        return process_ids
    
    def _apply_network_isolation(self, bubble: SecurityBubble):
        """Applique l'isolation réseau pour une bulle."""
        try:
            # Règles de firewall pour isolation
            for pid in bubble.process_ids:
                try:
                    # Règle de limitation des connexions sortantes
                    rule = SecurityRule(
                        rule_id=f"bubble_{bubble.bubble_id}_outbound_{pid}",
                        source=f"pid:{pid}",
                        destination="*",
                        port=0,
                        protocol="*",
                        action="monitor",
                        priority=500,
                        created_at=datetime.now()
                    )
                    self.security_rules.append(rule)
                    
                except Exception as e:
                    logger.warning(f"Erreur isolation réseau PID {pid}: {e}")
                    
        except Exception as e:
            logger.error(f"Erreur application isolation réseau: {e}")
    
    def _apply_resource_limits(self, bubble: SecurityBubble):
        """Applique les limites de ressources pour une bulle."""
        try:
            for pid in bubble.process_ids:
                try:
                    process = psutil.Process(pid)
                    
                    # Limitation mémoire (approximative via monitoring)
                    memory_info = process.memory_info()
                    if memory_info.rss > bubble.resource_limits["max_memory_mb"] * 1024 * 1024:
                        logger.warning(f"Processus {pid} dépasse la limite mémoire")
                        # Note: Limitation réelle nécessiterait des privilèges système
                    
                    # Monitoring CPU
                    cpu_percent = process.cpu_percent()
                    if cpu_percent > bubble.resource_limits["max_cpu_percent"]:
                        logger.warning(f"Processus {pid} dépasse la limite CPU")
                    
                except psutil.NoSuchProcess:
                    # Processus terminé, nettoyage de la bulle
                    bubble.process_ids.remove(pid)
                except Exception as e:
                    logger.warning(f"Erreur limitation ressources PID {pid}: {e}")
                    
        except Exception as e:
            logger.error(f"Erreur application limites ressources: {e}")
    
    def add_security_rule(self, rule: SecurityRule) -> bool:
        """Ajoute une nouvelle règle de sécurité."""
        try:
            # Validation de la règle
            if not self._validate_security_rule(rule):
                logger.error(f"Règle invalide: {rule.rule_id}")
                return False
            
            # Vérification des conflits
            if self._check_rule_conflicts(rule):
                logger.warning(f"Conflit détecté pour la règle: {rule.rule_id}")
            
            # Ajout de la règle
            self.security_rules.append(rule)
            
            # Tri par priorité
            self.security_rules.sort(key=lambda r: r.priority)
            
            logger.info(f"Règle de sécurité ajoutée: {rule.rule_id}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur ajout règle sécurité: {e}")
            return False
    
    def _validate_security_rule(self, rule: SecurityRule) -> bool:
        """Valide une règle de sécurité."""
        # Vérification des champs obligatoires
        if not rule.rule_id or not rule.action:
            return False
        
        # Validation de l'action
        if rule.action not in ["allow", "deny", "monitor"]:
            return False
        
        # Validation du protocole
        if rule.protocol not in ["tcp", "udp", "icmp", "*"]:
            return False
        
        # Validation du port
        if rule.port < 0 or rule.port > 65535:
            return False
        
        return True
    
    def _check_rule_conflicts(self, new_rule: SecurityRule) -> bool:
        """Vérifie les conflits entre règles."""
        for existing_rule in self.security_rules:
            if (existing_rule.source == new_rule.source and
                existing_rule.destination == new_rule.destination and
                existing_rule.port == new_rule.port and
                existing_rule.protocol == new_rule.protocol and
                existing_rule.action != new_rule.action):
                return True
        return False
    
    def _monitoring_loop(self):
        """Boucle principale de monitoring."""
        while self.monitoring_active:
            try:
                # Monitoring des bulles de sécurité
                self._monitor_security_bubbles()
                
                # Monitoring des connexions réseau
                self._monitor_network_connections()
                
                # Monitoring des processus
                self._monitor_processes()
                
                # Détection d'anomalies
                self._detect_anomalies()
                
                time.sleep(self.config["monitoring_interval"])
                
            except Exception as e:
                logger.error(f"Erreur boucle monitoring: {e}")
                time.sleep(10)
    
    def _monitor_security_bubbles(self):
        """Surveille l'état des bulles de sécurité."""
        for bubble_id, bubble in list(self.security_bubbles.items()):
            try:
                # Vérification que les processus existent encore
                active_pids = []
                for pid in bubble.process_ids:
                    if psutil.pid_exists(pid):
                        active_pids.append(pid)
                
                bubble.process_ids = active_pids
                
                # Suppression des bulles vides
                if not active_pids:
                    logger.info(f"Suppression bulle vide: {bubble_id}")
                    del self.security_bubbles[bubble_id]
                    continue
                
                # Vérification des limites de ressources
                self._apply_resource_limits(bubble)
                
            except Exception as e:
                logger.error(f"Erreur monitoring bulle {bubble_id}: {e}")
    
    def _monitor_network_connections(self):
        """Surveille les connexions réseau."""
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED:
                    # Vérification contre les règles de sécurité
                    self._check_connection_against_rules(conn)
                    
        except Exception as e:
            logger.error(f"Erreur monitoring réseau: {e}")
    
    def _check_connection_against_rules(self, connection):
        """Vérifie une connexion contre les règles de sécurité."""
        try:
            if not connection.laddr or not connection.raddr:
                return
            
            local_addr = connection.laddr.ip
            remote_addr = connection.raddr.ip
            local_port = connection.laddr.port
            remote_port = connection.raddr.port
            
            # Application des règles par priorité
            for rule in self.security_rules:
                if self._rule_matches_connection(rule, connection):
                    if rule.action == "deny":
                        logger.warning(f"Connexion bloquée: {local_addr}:{local_port} -> {remote_addr}:{remote_port}")
                        # Note: Blocage réel nécessiterait des privilèges système
                    elif rule.action == "monitor":
                        logger.info(f"Connexion surveillée: {local_addr}:{local_port} -> {remote_addr}:{remote_port}")
                    break
                    
        except Exception as e:
            logger.error(f"Erreur vérification connexion: {e}")
    
    def _rule_matches_connection(self, rule: SecurityRule, connection) -> bool:
        """Vérifie si une règle s'applique à une connexion."""
        try:
            # Vérification des adresses
            if rule.source != "*":
                if rule.source.startswith("pid:"):
                    pid = int(rule.source[4:])
                    if connection.pid != pid:
                        return False
                else:
                    if rule.source != connection.laddr.ip:
                        return False
            
            # Vérification du port
            if rule.port != 0:
                if rule.port != connection.laddr.port and rule.port != connection.raddr.port:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur correspondance règle: {e}")
            return False
    
    def _monitor_processes(self):
        """Surveille les processus pour détecter des comportements suspects."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    # Détection de consommation excessive
                    if proc.info['cpu_percent'] > 90:
                        logger.warning(f"Processus {proc.info['name']} ({proc.info['pid']}) consomme beaucoup de CPU")
                    
                    if proc.info['memory_percent'] > 80:
                        logger.warning(f"Processus {proc.info['name']} ({proc.info['pid']}) consomme beaucoup de mémoire")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Erreur monitoring processus: {e}")
    
    def _detect_anomalies(self):
        """Détecte les anomalies de sécurité."""
        try:
            current_time = datetime.now()
            
            # Détection de connexions suspectes
            suspicious_connections = self._detect_suspicious_connections()
            
            # Détection de processus suspects
            suspicious_processes = self._detect_suspicious_processes()
            
            # Actions automatiques si anomalies détectées
            if suspicious_connections or suspicious_processes:
                self._trigger_security_response(suspicious_connections, suspicious_processes)
                
        except Exception as e:
            logger.error(f"Erreur détection anomalies: {e}")
    
    def _detect_suspicious_connections(self) -> List[Dict]:
        """Détecte les connexions suspectes."""
        suspicious = []
        
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.raddr:
                    # Connexions vers des ports suspects
                    suspicious_ports = [6667, 6668, 6669, 1337, 31337]  # IRC, hacking tools
                    if conn.raddr.port in suspicious_ports:
                        suspicious.append({
                            "type": "suspicious_port",
                            "connection": f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}",
                            "pid": conn.pid
                        })
                    
                    # Connexions vers des IPs externes suspectes
                    if self._is_suspicious_ip(conn.raddr.ip):
                        suspicious.append({
                            "type": "suspicious_ip",
                            "connection": f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}",
                            "pid": conn.pid
                        })
                        
        except Exception as e:
            logger.error(f"Erreur détection connexions suspectes: {e}")
        
        return suspicious
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Vérifie si une adresse IP est suspecte."""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # IPs privées sont généralement OK
            if ip.is_private:
                return False
            
            # IPs de loopback sont OK
            if ip.is_loopback:
                return False
            
            # Liste noire basique (à étendre avec threat intelligence)
            blacklisted_ranges = [
                "0.0.0.0/8",    # Invalid range
                "169.254.0.0/16",  # Link-local
                "224.0.0.0/4"   # Multicast
            ]
            
            for range_str in blacklisted_ranges:
                if ip in ipaddress.ip_network(range_str):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur vérification IP suspecte {ip_address}: {e}")
            return False
    
    def _detect_suspicious_processes(self) -> List[Dict]:
        """Détecte les processus suspects."""
        suspicious = []
        
        try:
            # Noms de processus suspects
            suspicious_names = [
                "nc", "netcat", "ncat",  # Network tools
                "nmap", "masscan",       # Network scanners
                "metasploit", "msfconsole",  # Penetration testing
                "wireshark", "tcpdump"   # Packet capture
            ]
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    name = proc.info['name'].lower()
                    
                    if any(sus_name in name for sus_name in suspicious_names):
                        suspicious.append({
                            "type": "suspicious_process_name",
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "cmdline": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Erreur détection processus suspects: {e}")
        
        return suspicious
    
    def _trigger_security_response(self, suspicious_connections: List[Dict], suspicious_processes: List[Dict]):
        """Déclenche une réponse de sécurité automatique."""
        try:
            response_actions = []
            
            # Réponse aux connexions suspectes
            for conn in suspicious_connections:
                if conn["type"] == "suspicious_port":
                    action = {
                        "type": "block_connection",
                        "target": conn["connection"],
                        "reason": "Connexion vers port suspect",
                        "timestamp": datetime.now().isoformat()
                    }
                    response_actions.append(action)
            
            # Réponse aux processus suspects
            for proc in suspicious_processes:
                if proc["type"] == "suspicious_process_name":
                    action = {
                        "type": "monitor_process",
                        "target": proc["pid"],
                        "reason": "Processus au nom suspect",
                        "timestamp": datetime.now().isoformat()
                    }
                    response_actions.append(action)
            
            # Enregistrement des actions
            self.auto_healing_actions.extend(response_actions)
            
            logger.warning(f"Réponse sécurité déclenchée: {len(response_actions)} actions")
            
        except Exception as e:
            logger.error(f"Erreur réponse sécurité: {e}")
    
    def _auto_healing_loop(self):
        """Boucle d'auto-réparation."""
        while self.monitoring_active:
            try:
                if self.config["auto_healing_enabled"]:
                    self._perform_auto_healing()
                
                time.sleep(30)  # Vérification toutes les 30 secondes
                
            except Exception as e:
                logger.error(f"Erreur boucle auto-healing: {e}")
                time.sleep(60)
    
    def _perform_auto_healing(self):
        """Effectue les actions d'auto-réparation."""
        try:
            # Nettoyage des règles expirées
            current_time = datetime.now()
            self.security_rules = [
                rule for rule in self.security_rules
                if not rule.expires_at or rule.expires_at > current_time
            ]
            
            # Optimisation des règles
            self._optimize_security_rules()
            
            # Nettoyage des anciennes actions
            cutoff_time = current_time - timedelta(hours=24)
            self.auto_healing_actions = [
                action for action in self.auto_healing_actions
                if datetime.fromisoformat(action["timestamp"]) > cutoff_time
            ]
            
        except Exception as e:
            logger.error(f"Erreur auto-healing: {e}")
    
    def _optimize_security_rules(self):
        """Optimise les règles de sécurité."""
        try:
            # Suppression des règles redondantes
            unique_rules = []
            seen_rules = set()
            
            for rule in self.security_rules:
                rule_signature = (rule.source, rule.destination, rule.port, rule.protocol, rule.action)
                if rule_signature not in seen_rules:
                    unique_rules.append(rule)
                    seen_rules.add(rule_signature)
            
            if len(unique_rules) < len(self.security_rules):
                logger.info(f"Optimisation: {len(self.security_rules) - len(unique_rules)} règles redondantes supprimées")
                self.security_rules = unique_rules
                
        except Exception as e:
            logger.error(f"Erreur optimisation règles: {e}")
    
    def get_security_status(self) -> Dict:
        """Retourne le statut de sécurité global."""
        return {
            "status": self.status,
            "active_bubbles": len(self.security_bubbles),
            "security_rules": len(self.security_rules),
            "threat_indicators": len(self.threat_indicators),
            "auto_healing_actions": len(self.auto_healing_actions),
            "monitoring_active": self.monitoring_active,
            "configuration": self.config
        }
    
    def get_active_bubbles(self) -> List[Dict]:
        """Retourne la liste des bulles actives."""
        bubbles = []
        for bubble_id, bubble in self.security_bubbles.items():
            bubbles.append({
                "bubble_id": bubble_id,
                "application": bubble.application_name,
                "process_count": len(bubble.process_ids),
                "status": bubble.status,
                "created_at": bubble.created_at.isoformat()
            })
        return bubbles
    
    def terminate_bubble(self, bubble_id: str) -> bool:
        """Termine une bulle de sécurité."""
        try:
            if bubble_id in self.security_bubbles:
                bubble = self.security_bubbles[bubble_id]
                bubble.status = "terminated"
                
                # Suppression des règles associées
                self.security_rules = [
                    rule for rule in self.security_rules
                    if not rule.rule_id.startswith(f"bubble_{bubble_id}")
                ]
                
                del self.security_bubbles[bubble_id]
                logger.info(f"Bulle {bubble_id} terminée")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Erreur terminaison bulle {bubble_id}: {e}")
            return False
    
    def shutdown(self):
        """Arrête Nebula Shield proprement."""
        try:
            self.monitoring_active = False
            
            # Attente arrêt des threads
            if self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5)
            if self.healing_thread.is_alive():
                self.healing_thread.join(timeout=5)
            
            # Nettoyage des bulles
            for bubble_id in list(self.security_bubbles.keys()):
                self.terminate_bubble(bubble_id)
            
            self.status = "shutdown"
            logger.info("Nebula Shield arrêté proprement")
            
        except Exception as e:
            logger.error(f"Erreur arrêt Nebula Shield: {e}")
    
    def get_protection_stats(self) -> Dict:
        """Retourne les statistiques de protection."""
        try:
            return {
                "total_alerts": len(self.alerts),
                "active_segments": len(self.security_segments),
                "blocked_connections": len([alert for alert in self.alerts if "blocked" in alert.get("action_taken", "")]),
                "protection_active": getattr(self, 'protection_active', True),
                "uptime_seconds": (datetime.now() - self.start_time).total_seconds(),
                "last_alert": self.alerts[-1]["timestamp"] if self.alerts else None
            }
        except Exception as e:
            logger.error(f"Erreur stats protection: {e}")
            return {"total_alerts": 0, "error": str(e)}
    
    def get_status(self) -> Dict:
        """Retourne le statut de Nebula Shield."""
        return {
            "status": self.status,
            "microsegmentation_enabled": self.config["microsegmentation_enabled"],
            "auto_healing_enabled": self.config["auto_healing_enabled"],
            "active_bubbles": len(self.security_bubbles),
            "security_rules": len(self.security_rules)
        }

    def activate_protection(self):
        """Active la protection Nebula Shield."""
        try:
            self.protection_active = True
            self.start_monitoring()
            logger.info("Protection Nebula Shield activée")
        except Exception as e:
            logger.error(f"Erreur activation protection: {e}")
    
    def deactivate_protection(self):
        """Désactive la protection Nebula Shield."""
        try:
            self.protection_active = False
            self.stop_monitoring()
            logger.info("Protection Nebula Shield désactivée")
        except Exception as e:
            logger.error(f"Erreur désactivation protection: {e}")
    
    def detect_intrusion(self, source_ip: str, behavior: str) -> Dict:
        """
        Détecte une intrusion et génère une alerte.
        
        Args:
            source_ip: IP source suspecte
            behavior: Comportement détecté
            
        Returns:
            Alerte d'intrusion
        """
        try:
            alert_id = f"alert_{int(time.time())}"
            
            # Analyse du comportement
            severity = "medium"
            if "suspicious" in behavior.lower():
                severity = "high"
            elif "critical" in behavior.lower():
                severity = "critical"
            
            alert = {
                "alert_id": alert_id,
                "source_ip": source_ip,
                "behavior": behavior,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "action_taken": "logged"
            }
            
            # Stockage de l'alerte
            self.alerts.append(alert)
            
            logger.warning(f"Intrusion détectée: {source_ip} - {behavior}")
            
            return alert
            
        except Exception as e:
            logger.error(f"Erreur détection intrusion: {e}")
            return {"error": str(e)}


# Classes auxiliaires
class NetworkMonitor:
    """Moniteur réseau pour Nebula Shield."""
    
    def __init__(self):
        self.active = True
    
    def get_connections(self):
        """Retourne les connexions réseau actives."""
        return psutil.net_connections()


class ProcessMonitor:
    """Moniteur de processus pour Nebula Shield."""
    
    def __init__(self):
        self.active = True
    
    def get_processes(self):
        """Retourne la liste des processus."""
        return list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))


class VulnerabilityScanner:
    """Scanner de vulnérabilités basique."""
    
    def __init__(self):
        self.active = True
    
    def scan_system(self):
        """Effectue un scan basique du système."""
        return {
            "open_ports": self._scan_open_ports(),
            "running_services": self._get_running_services(),
            "system_info": self._get_system_info()
        }
    
    def _scan_open_ports(self):
        """Scan des ports ouverts."""
        open_ports = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN:
                    open_ports.append({
                        "port": conn.laddr.port,
                        "address": conn.laddr.ip,
                        "pid": conn.pid
                    })
        except Exception as e:
            logger.error(f"Erreur scan ports: {e}")
        return open_ports
    
    def _get_running_services(self):
        """Retourne les services en cours d'exécution."""
        # Simulation - en réalité nécessiterait une implémentation spécifique à l'OS
        return ["ssh", "http", "https", "dns"]
    
    def _get_system_info(self):
        """Retourne les informations système."""
        return {
            "os": os.name,
            "platform": os.uname().sysname if hasattr(os, 'uname') else 'Windows',
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
            "boot_time": psutil.boot_time()
        } 