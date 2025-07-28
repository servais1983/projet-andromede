#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Neural Sandbox
Environnement virtuel isolé pour l'analyse sécurisée des fichiers suspects.
"""

import os
import tempfile
import json
import logging
import hashlib
import shutil
import subprocess
import threading
import time
import signal
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

# Imports conditionnels
try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    logging.warning("Docker non disponible pour Neural Sandbox")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil non disponible pour Neural Sandbox")

logger = logging.getLogger(__name__)

class NeuralSandbox:
    """
    Environnement sandbox pour l'analyse sécurisée de fichiers suspects.
    Utilise la containerisation et l'isolation pour empêcher les dommages.
    """
    
    def __init__(self):
        """Initialise le Neural Sandbox."""
        self.sandbox_dir = Path(tempfile.gettempdir()) / "andromede_sandbox"
        self.sandbox_dir.mkdir(exist_ok=True)
        
        self.running_analyses = {}
        self.analysis_history = []
        self.status = "initializing"
        
        # Configuration du sandbox
        self.config = {
            "max_execution_time": 30,  # secondes
            "max_memory_mb": 512,
            "max_cpu_percent": 50,
            "network_isolated": True,
            "file_system_readonly": True
        }
        
        # Initialisation Docker si disponible
        self.docker_available = self._check_docker_availability()
        
        # Création des répertoires d'isolation
        self._setup_sandbox_environment()
        
        self.status = "operational"
        logger.info("Neural Sandbox initialisé avec succès")
    
    def _check_docker_availability(self) -> bool:
        """Vérifie si Docker est disponible."""
        if not DOCKER_AVAILABLE:
            logger.warning("Module Docker non disponible")
            self.docker_client = None
            return False
        
        try:
            docker_client = docker.from_env()
            docker_client.ping()
            self.docker_client = docker_client
            logger.info("Docker détecté et configuré")
            return True
        except Exception as e:
            logger.warning(f"Docker non disponible: {e}")
            self.docker_client = None
            return False
    
    def _setup_sandbox_environment(self):
        """Configure l'environnement sandbox."""
        # Répertoires isolés
        self.isolated_dirs = {
            "input": self.sandbox_dir / "input",
            "output": self.sandbox_dir / "output",
            "logs": self.sandbox_dir / "logs",
            "temp": self.sandbox_dir / "temp"
        }
        
        for dir_path in self.isolated_dirs.values():
            dir_path.mkdir(exist_ok=True)
        
        # Scripts d'analyse
        self._create_analysis_scripts()
    
    def _create_analysis_scripts(self):
        """Crée les scripts d'analyse pour le sandbox."""
        scripts_dir = self.sandbox_dir / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        
        # Script d'analyse de fichier
        file_analysis_script = scripts_dir / "analyze_file.py"
        file_analysis_script.write_text('''
import os
import sys
import json
import hashlib
from datetime import datetime

def analyze_file(file_path):
    """Analyse basique d'un fichier."""
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    
    try:
        # Informations de base
        stat = os.stat(file_path)
        with open(file_path, 'rb') as f:
            content = f.read()
        
        file_hash = hashlib.sha256(content).hexdigest()
        
        try:
            # Tentative de détection du type MIME basique
            if content.startswith(b'\\x89PNG'):
                file_type = "image/png"
            elif content.startswith(b'\\xff\\xd8\\xff'):
                file_type = "image/jpeg"
            elif content.startswith(b'%PDF'):
                file_type = "application/pdf"
            elif content.startswith(b'PK'):
                file_type = "application/zip"
            else:
                file_type = "application/octet-stream"
        except:
            file_type = "unknown"
        
        # Analyse du contenu
        strings_found = []
        try:
            text_content = content.decode('utf-8', errors='ignore')
            # Recherche de patterns suspects
            suspicious_patterns = [
                'eval(', 'exec(', 'system(', 'shell_exec',
                'base64_decode', 'gzuncompress', 'str_rot13'
            ]
            for pattern in suspicious_patterns:
                if pattern in text_content:
                    strings_found.append(pattern)
        except:
            pass
        
        return {
            "filename": os.path.basename(file_path),
            "size": stat.st_size,
            "hash_sha256": file_hash,
            "file_type": file_type,
            "suspicious_strings": strings_found,
            "analysis_time": datetime.now().isoformat(),
            "is_suspicious": len(strings_found) > 0
        }
    
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_file.py <file_path>")
        sys.exit(1)
    
    result = analyze_file(sys.argv[1])
    print(json.dumps(result, indent=2))
''')
    
    def analyze_file(self, file_path: str, analysis_type: str = "comprehensive") -> Dict:
        """
        Analyse un fichier dans l'environnement sandbox.
        
        Args:
            file_path: Chemin vers le fichier à analyser
            analysis_type: Type d'analyse (basic, comprehensive, deep)
            
        Returns:
            Résultats de l'analyse
        """
        try:
            analysis_id = hashlib.md5(f"{file_path}{time.time()}".encode()).hexdigest()[:8]
            
            # Préparation de l'analyse
            analysis_config = {
                "analysis_id": analysis_id,
                "file_path": file_path,
                "analysis_type": analysis_type,
                "start_time": datetime.now(),
                "status": "running"
            }
            
            self.running_analyses[analysis_id] = analysis_config
            
            # Copie sécurisée du fichier dans le sandbox
            sandbox_file_path = self._copy_file_to_sandbox(file_path, analysis_id)
            
            if self.docker_available:
                result = self._analyze_with_docker(sandbox_file_path, analysis_type)
            else:
                result = self._analyze_with_process_isolation(sandbox_file_path, analysis_type)
            
            # Finalisation
            analysis_config["status"] = "completed"
            analysis_config["end_time"] = datetime.now()
            analysis_config["result"] = result
            
            # Ajout à l'historique
            self.analysis_history.append(analysis_config)
            
            # Nettoyage
            self._cleanup_analysis(analysis_id)
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur analyse sandbox: {e}")
            return {"error": f"Analyse échouée: {str(e)}"}
    
    def _copy_file_to_sandbox(self, file_path: str, analysis_id: str) -> str:
        """Copie un fichier dans l'environnement sandbox de manière sécurisée."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Fichier non trouvé: {file_path}")
        
        # Vérification de la taille
        file_size = os.path.getsize(file_path)
        if file_size > 100 * 1024 * 1024:  # 100MB max
            raise ValueError("Fichier trop volumineux pour l'analyse")
        
        # Copie sécurisée
        sandbox_filename = f"{analysis_id}_{os.path.basename(file_path)}"
        sandbox_file_path = self.isolated_dirs["input"] / sandbox_filename
        
        shutil.copy2(file_path, sandbox_file_path)
        
        # Permissions restrictives
        os.chmod(sandbox_file_path, 0o644)
        
        return str(sandbox_file_path)
    
    def _analyze_with_docker(self, file_path: str, analysis_type: str) -> Dict:
        """Analyse avec Docker pour isolation maximale."""
        try:
            # Création d'un conteneur d'analyse
            container_config = {
                "image": "python:3.9-slim",
                "command": f"python /scripts/analyze_file.py /input/{os.path.basename(file_path)}",
                "volumes": {
                    str(self.sandbox_dir / "scripts"): {"bind": "/scripts", "mode": "ro"},
                    str(self.isolated_dirs["input"]): {"bind": "/input", "mode": "ro"},
                    str(self.isolated_dirs["output"]): {"bind": "/output", "mode": "rw"}
                },
                "network_mode": "none",  # Pas d'accès réseau
                "mem_limit": f"{self.config['max_memory_mb']}m",
                "cpu_quota": int(100000 * self.config['max_cpu_percent'] / 100),
                "remove": True,
                "timeout": self.config['max_execution_time']
            }
            
            # Exécution du conteneur
            container = self.docker_client.containers.run(**container_config, detach=True)
            
            # Attente de fin d'exécution avec timeout
            try:
                result = container.wait(timeout=self.config['max_execution_time'])
                logs = container.logs().decode('utf-8')
                
                # Parsing du résultat
                if result['StatusCode'] == 0:
                    try:
                        analysis_result = json.loads(logs)
                        analysis_result["sandbox_method"] = "docker"
                        analysis_result["isolation_level"] = "maximum"
                        return analysis_result
                    except json.JSONDecodeError:
                        return {"error": "Format de résultat invalide", "logs": logs}
                else:
                    return {"error": f"Analyse échouée (code {result['StatusCode']})", "logs": logs}
                    
            except Exception as e:
                return {"error": f"Erreur conteneur: {str(e)}"}
                
        except Exception as e:
            logger.error(f"Erreur analyse Docker: {e}")
            return self._analyze_with_process_isolation(file_path, analysis_type)
    
    def _analyze_with_process_isolation(self, file_path: str, analysis_type: str) -> Dict:
        """Analyse avec isolation de processus comme fallback."""
        try:
            # Création d'un processus isolé
            script_path = self.sandbox_dir / "scripts" / "analyze_file.py"
            
            # Commande d'exécution
            cmd = [
                "python", str(script_path), file_path
            ]
            
            # Exécution avec limitations
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.isolated_dirs["temp"]),
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            # Surveillance du processus
            monitor_thread = threading.Thread(
                target=self._monitor_process,
                args=(process, self.config['max_execution_time'])
            )
            monitor_thread.start()
            
            # Attente du résultat
            try:
                stdout, stderr = process.communicate(timeout=self.config['max_execution_time'])
                
                if process.returncode == 0:
                    result = json.loads(stdout.decode('utf-8'))
                    result["sandbox_method"] = "process_isolation"
                    result["isolation_level"] = "medium"
                    return result
                else:
                    return {
                        "error": f"Processus échoué (code {process.returncode})",
                        "stderr": stderr.decode('utf-8')
                    }
                    
            except subprocess.TimeoutExpired:
                # Timeout - tuer le processus
                if os.name != 'nt':
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    except:
                        process.terminate()
                else:
                    process.terminate()
                
                return {"error": "Timeout d'analyse dépassé"}
                
        except Exception as e:
            logger.error(f"Erreur isolation processus: {e}")
            return {"error": f"Échec analyse: {str(e)}"}
    
    def _monitor_process(self, process: subprocess.Popen, timeout: int):
        """Surveille un processus et applique les limites de ressources."""
        start_time = time.time()
        
        while process.poll() is None:
            try:
                # Vérification du timeout
                if time.time() - start_time > timeout:
                    process.terminate()
                    break
                
                # Vérification des ressources si psutil est disponible
                if PSUTIL_AVAILABLE:
                    try:
                        proc = psutil.Process(process.pid)
                        
                        # Limitation mémoire
                        memory_mb = proc.memory_info().rss / 1024 / 1024
                        if memory_mb > self.config['max_memory_mb']:
                            logger.warning(f"Processus {process.pid} dépasse la limite mémoire")
                            process.terminate()
                            break
                        
                        # Limitation CPU (approximative)
                        cpu_percent = proc.cpu_percent()
                        if cpu_percent > self.config['max_cpu_percent']:
                            logger.warning(f"Processus {process.pid} dépasse la limite CPU")
                            time.sleep(0.1)  # Throttling basique
                            
                    except Exception:
                        break
                        
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Erreur monitoring processus: {e}")
                break
    
    def _cleanup_analysis(self, analysis_id: str):
        """Nettoie les fichiers d'une analyse."""
        try:
            # Suppression des fichiers temporaires
            for dir_path in self.isolated_dirs.values():
                for file_path in dir_path.glob(f"{analysis_id}_*"):
                    file_path.unlink(missing_ok=True)
            
            # Suppression de l'entrée des analyses en cours
            if analysis_id in self.running_analyses:
                del self.running_analyses[analysis_id]
                
        except Exception as e:
            logger.error(f"Erreur nettoyage analyse {analysis_id}: {e}")
    
    def analyze_behavior(self, file_path: str, duration: int = 30) -> Dict:
        """
        Analyse comportementale d'un fichier en exécution.
        
        Args:
            file_path: Chemin vers le fichier à analyser
            duration: Durée d'observation en secondes
            
        Returns:
            Analyse comportementale
        """
        try:
            analysis_id = hashlib.md5(f"behavior_{file_path}{time.time()}".encode()).hexdigest()[:8]
            
            # Préparation de l'environnement d'exécution
            sandbox_file = self._copy_file_to_sandbox(file_path, analysis_id)
            
            behavior_data = {
                "analysis_id": analysis_id,
                "file_analyzed": os.path.basename(file_path),
                "start_time": datetime.now().isoformat(),
                "duration": duration,
                "process_activity": [],
                "network_activity": [],
                "file_system_activity": [],
                "registry_activity": [],
                "behavior_score": 0
            }
            
            if self.docker_available:
                # Analyse comportementale avec Docker
                behavior_data.update(self._behavioral_analysis_docker(sandbox_file, duration))
            else:
                # Analyse comportementale avec processus isolé
                behavior_data.update(self._behavioral_analysis_process(sandbox_file, duration))
            
            # Calcul du score de comportement
            behavior_data["behavior_score"] = self._calculate_behavior_score(behavior_data)
            
            return behavior_data
            
        except Exception as e:
            logger.error(f"Erreur analyse comportementale: {e}")
            return {"error": f"Analyse comportementale échouée: {str(e)}"}
    
    def _behavioral_analysis_docker(self, file_path: str, duration: int) -> Dict:
        """Analyse comportementale avec Docker."""
        # Simulation d'analyse comportementale
        return {
            "method": "docker_behavioral",
            "isolation_level": "maximum",
            "observed_behaviors": [
                "File creation attempts",
                "Network connection attempts",
                "Process spawning"
            ],
            "suspicious_activities": [],
            "threat_indicators": []
        }
    
    def _behavioral_analysis_process(self, file_path: str, duration: int) -> Dict:
        """Analyse comportementale avec processus isolé."""
        # Simulation d'analyse comportementale
        return {
            "method": "process_behavioral", 
            "isolation_level": "medium",
            "observed_behaviors": [
                "Limited file system access",
                "Process monitoring active"
            ],
            "suspicious_activities": [],
            "threat_indicators": []
        }
    
    def _calculate_behavior_score(self, behavior_data: Dict) -> int:
        """Calcule un score de comportement suspect."""
        score = 0
        
        # Analyse des activités suspectes
        if behavior_data.get("suspicious_activities"):
            score += len(behavior_data["suspicious_activities"]) * 20
        
        if behavior_data.get("threat_indicators"):
            score += len(behavior_data["threat_indicators"]) * 30
        
        # Score basé sur les types d'activités
        activities = behavior_data.get("observed_behaviors", [])
        for activity in activities:
            if "network" in activity.lower():
                score += 15
            if "registry" in activity.lower():
                score += 10
            if "process" in activity.lower():
                score += 5
        
        return min(100, score)
    
    def get_analysis_history(self, limit: int = 10) -> List[Dict]:
        """Retourne l'historique des analyses."""
        return self.analysis_history[-limit:]
    
    def get_running_analyses(self) -> Dict:
        """Retourne les analyses en cours."""
        return {
            "count": len(self.running_analyses),
            "analyses": list(self.running_analyses.values())
        }
    
    def terminate_analysis(self, analysis_id: str) -> bool:
        """Termine une analyse en cours."""
        if analysis_id in self.running_analyses:
            try:
                # Nettoyage forcé
                self._cleanup_analysis(analysis_id)
                logger.info(f"Analyse {analysis_id} terminée")
                return True
            except Exception as e:
                logger.error(f"Erreur terminaison analyse {analysis_id}: {e}")
                return False
        return False
    
    def get_sandbox_stats(self) -> Dict:
        """Retourne les statistiques du sandbox."""
        return {
            "total_analyses": len(self.analysis_history),
            "running_analyses": len(self.running_analyses),
            "docker_available": self.docker_available,
            "psutil_available": PSUTIL_AVAILABLE,
            "sandbox_directory": str(self.sandbox_dir),
            "disk_usage": self._get_disk_usage(),
            "configuration": self.config
        }
    
    def _get_disk_usage(self) -> Dict:
        """Calcule l'utilisation disque du sandbox."""
        try:
            total_size = 0
            file_count = 0
            
            for dir_path in self.isolated_dirs.values():
                for file_path in dir_path.rglob("*"):
                    if file_path.is_file():
                        total_size += file_path.stat().st_size
                        file_count += 1
            
            return {
                "total_size_mb": round(total_size / 1024 / 1024, 2),
                "file_count": file_count
            }
        except Exception:
            return {"total_size_mb": 0, "file_count": 0}
    
    def cleanup_old_analyses(self, days_old: int = 7):
        """Nettoie les anciennes analyses."""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            cleaned_count = 0
            
            # Nettoyage de l'historique
            self.analysis_history = [
                analysis for analysis in self.analysis_history
                if analysis.get("start_time", datetime.now()) > cutoff_date
            ]
            
            # Nettoyage des fichiers
            for dir_path in self.isolated_dirs.values():
                for file_path in dir_path.iterdir():
                    if file_path.is_file():
                        file_age = datetime.fromtimestamp(file_path.stat().st_mtime)
                        if file_age < cutoff_date:
                            file_path.unlink()
                            cleaned_count += 1
            
            logger.info(f"Nettoyage sandbox: {cleaned_count} fichiers supprimés")
            
        except Exception as e:
            logger.error(f"Erreur nettoyage sandbox: {e}")
    
    def get_status(self) -> Dict:
        """Retourne le statut du Neural Sandbox."""
        return {
            "status": self.status,
            "docker_available": self.docker_available,
            "psutil_available": PSUTIL_AVAILABLE,
            "running_analyses": len(self.running_analyses),
            "total_analyses": len(self.analysis_history)
        } 