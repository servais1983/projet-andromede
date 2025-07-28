#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - StarMap Threat Visualizer
Interface 3D immersive pour la visualisation des menaces de sécurité.
"""

import json
import logging
import math
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import numpy as np

# Import conditionnel des librairies 3D
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    plotly_available = True
except ImportError:
    plotly_available = False
    logging.warning("Plotly non disponible - visualisation limitée")

try:
    import matplotlib.pyplot as plt
    from mpl_toolkits.mplot3d import Axes3D
    matplotlib_available = True
except ImportError:
    matplotlib_available = False
    logging.warning("Matplotlib non disponible")

logger = logging.getLogger(__name__)

class ThreatObject3D:
    """Objet 3D représentant une menace dans l'espace."""
    
    def __init__(self, threat_id: str, threat_type: str, position: Tuple[float, float, float],
                 severity: str, size: float = 1.0, color: str = "red"):
        self.threat_id = threat_id
        self.threat_type = threat_type
        self.position = position  # (x, y, z)
        self.severity = severity
        self.size = size
        self.color = color
        self.velocity = (0.0, 0.0, 0.0)  # Mouvement dans l'espace
        self.created_at = datetime.now()
        self.last_update = datetime.now()
        self.metadata = {}

class DefenseObject3D:
    """Objet 3D représentant une défense dans l'espace."""
    
    def __init__(self, defense_id: str, defense_type: str, position: Tuple[float, float, float],
                 strength: float = 1.0, radius: float = 5.0, color: str = "blue"):
        self.defense_id = defense_id
        self.defense_type = defense_type
        self.position = position
        self.strength = strength
        self.radius = radius  # Rayon de protection
        self.color = color
        self.active = True
        self.created_at = datetime.now()
        self.metadata = {}

class StarMapVisualizer:
    """
    Visualiseur 3D immersif StarMap pour les menaces de sécurité.
    Représente l'environnement numérique comme un système stellaire.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialise le visualiseur StarMap.
        
        Args:
            config: Configuration du visualiseur
        """
        self.config = config or self._load_default_config()
        self.status = "initializing"
        
        # Objets 3D
        self.threats: Dict[str, ThreatObject3D] = {}
        self.defenses: Dict[str, DefenseObject3D] = {}
        self.assets: Dict[str, Dict] = {}  # Systèmes protégés
        
        # Animation et rendu
        self.animation_active = False
        self.animation_thread = None
        self.last_render_time = datetime.now()
        
        # Données de visualisation
        self.threat_history: List[Dict] = []
        self.attack_vectors: List[Dict] = []
        self.defense_activities: List[Dict] = []
        
        # Configuration 3D
        self.scene_bounds = (-100, 100, -100, 100, -100, 100)  # x_min, x_max, y_min, y_max, z_min, z_max
        self.camera_position = (50, 50, 50)
        self.camera_target = (0, 0, 0)
        
        # Mapping des couleurs par sévérité
        self.severity_colors = {
            "critical": "#FF0000",  # Rouge vif
            "high": "#FF6600",      # Orange
            "medium": "#FFAA00",    # Jaune-orange
            "low": "#FFFF00",       # Jaune
            "info": "#00FF00"       # Vert
        }
        
        # Types de défenses
        self.defense_colors = {
            "firewall": "#0066FF",      # Bleu
            "antivirus": "#00FFFF",     # Cyan
            "ids": "#9900FF",           # Violet
            "sandbox": "#FF00FF",       # Magenta
            "honeypot": "#FFAA99"       # Rose
        }
        
        self._initialize_default_scene()
        
        self.status = "operational"
        logger.info("StarMap Visualizer initialisé")
    
    def _load_default_config(self) -> Dict:
        """Charge la configuration par défaut."""
        return {
            "rendering_mode": "3D",           # 3D, 2D, hybrid
            "theme": "dark",                  # dark, light, space
            "refresh_rate": 5,                # Secondes entre mises à jour
            "max_objects": 1000,              # Nombre max d'objets affichés
            "animation_speed": 1.0,           # Vitesse d'animation
            "auto_rotate": True,              # Rotation automatique de la vue
            "show_connections": True,         # Afficher les connexions
            "show_attack_paths": True,        # Afficher les chemins d'attaque
            "particle_effects": True,        # Effets de particules
            "vr_mode": False,                 # Mode VR/AR
            "immersive_audio": False          # Audio immersif
        }
    
    def _initialize_default_scene(self):
        """Initialise la scène 3D par défaut."""
        # Ajout d'un système central (le cœur du réseau)
        self.add_asset("core_system", {
            "name": "Core Network",
            "type": "central_system",
            "position": (0, 0, 0),
            "size": 10,
            "color": "#FFFFFF",
            "importance": "critical"
        })
        
        # Ajout de défenses par défaut
        default_defenses = [
            ("firewall_main", "firewall", (-20, 0, 0), 8.0, 15.0),
            ("antivirus_core", "antivirus", (20, 0, 0), 7.0, 12.0),
            ("ids_perimeter", "ids", (0, -20, 0), 6.0, 18.0),
            ("sandbox_analysis", "sandbox", (0, 20, 0), 5.0, 10.0)
        ]
        
        for def_id, def_type, pos, strength, radius in default_defenses:
            self.add_defense(def_id, def_type, pos, strength, radius)
        
        logger.info("Scène 3D par défaut initialisée")
    
    def add_threat(self, threat_data: Dict):
        """
        Ajoute une menace à la visualisation.
        
        Args:
            threat_data: Dictionnaire contenant les données de la menace
        """
        try:
            threat_id = threat_data.get("id", f"threat_{len(self.threats)}")
            
            threat = {
                "id": threat_id,
                "name": threat_data.get("name", f"Threat {threat_id}"),
                "type": threat_data.get("type", "unknown"),
                "severity": threat_data.get("severity", "medium"),
                "position": self._generate_position(),
                "timestamp": datetime.now(),
                "source_ip": threat_data.get("source_ip", "unknown"),
                "target_ip": threat_data.get("target_ip", "unknown"),
                "status": "active"
            }
            
            self.threats[threat_id] = threat
            logger.info(f"Menace ajoutée: {threat_id}")
            
        except Exception as e:
            logger.error(f"Erreur ajout menace: {e}")
    
    def _generate_position(self) -> Tuple[float, float, float]:
        """Génère une position 3D aléatoire."""
        import random
        return (
            random.uniform(-10, 10),
            random.uniform(-10, 10), 
            random.uniform(-10, 10)
        )
    
    def _calculate_threat_position(self, threat_type: str, threat_data: Dict) -> Tuple[float, float, float]:
        """Calcule la position 3D d'une menace."""
        # Position basée sur le type de menace et les données
        base_positions = {
            "malware": (30, 30, 20),
            "phishing": (-30, 30, 20),
            "ddos": (0, 40, 30),
            "intrusion": (-20, -20, 25),
            "data_breach": (20, -20, 25),
            "ransomware": (0, 0, 40)
        }
        
        base_pos = base_positions.get(threat_type, (0, 30, 20))
        
        # Ajout de variation aléatoire
        import random
        variation = 10
        x = base_pos[0] + random.uniform(-variation, variation)
        y = base_pos[1] + random.uniform(-variation, variation)
        z = base_pos[2] + random.uniform(-variation/2, variation/2)
        
        # Limitation aux bornes de la scène
        x = max(self.scene_bounds[0], min(self.scene_bounds[1], x))
        y = max(self.scene_bounds[2], min(self.scene_bounds[3], y))
        z = max(self.scene_bounds[4], min(self.scene_bounds[5], z))
        
        return (x, y, z)
    
    def _calculate_threat_size(self, severity: str) -> float:
        """Calcule la taille d'une menace basée sur sa sévérité."""
        size_mapping = {
            "critical": 8.0,
            "high": 6.0,
            "medium": 4.0,
            "low": 2.0,
            "info": 1.0
        }
        return size_mapping.get(severity, 4.0)
    
    def _calculate_threat_velocity(self, threat_obj: ThreatObject3D, threat_data: Dict) -> Tuple[float, float, float]:
        """Calcule la vélocité d'une menace vers sa cible."""
        target = threat_data.get("target", "core_system")
        
        # Recherche de la position de la cible
        target_pos = (0, 0, 0)  # Par défaut le centre
        
        if target in self.assets:
            target_pos = self.assets[target]["position"]
        
        # Calcul du vecteur de direction
        dx = target_pos[0] - threat_obj.position[0]
        dy = target_pos[1] - threat_obj.position[1]
        dz = target_pos[2] - threat_obj.position[2]
        
        # Normalisation et application de vitesse
        distance = math.sqrt(dx*dx + dy*dy + dz*dz)
        if distance > 0:
            speed = 0.5  # Vitesse de base
            velocity = (
                (dx / distance) * speed,
                (dy / distance) * speed,
                (dz / distance) * speed
            )
        else:
            velocity = (0, 0, 0)
        
        return velocity
    
    def add_defense(self, defense_id: str, defense_type: str, position: Tuple[float, float, float],
                   strength: float = 1.0, radius: float = 5.0) -> bool:
        """
        Ajoute une défense à la visualisation.
        
        Args:
            defense_id: Identifiant de la défense
            defense_type: Type de défense
            position: Position 3D
            strength: Force de la défense
            radius: Rayon de protection
            
        Returns:
            True si ajoutée avec succès
        """
        try:
            color = self.defense_colors.get(defense_type, "#0066FF")
            
            defense_obj = DefenseObject3D(
                defense_id=defense_id,
                defense_type=defense_type,
                position=position,
                strength=strength,
                radius=radius,
                color=color
            )
            
            self.defenses[defense_id] = defense_obj
            
            # Ajout à l'activité de défense
            self.defense_activities.append({
                "defense_id": defense_id,
                "defense_type": defense_type,
                "position": position,
                "timestamp": datetime.now().isoformat(),
                "action": "activated"
            })
            
            logger.info(f"Défense ajoutée à StarMap: {defense_id} ({defense_type})")
            return True
            
        except Exception as e:
            logger.error(f"Erreur ajout défense StarMap: {e}")
            return False
    
    def add_asset(self, asset_id: str, asset_data: Dict) -> bool:
        """
        Ajoute un asset (système protégé) à la visualisation.
        
        Args:
            asset_id: Identifiant de l'asset
            asset_data: Données de l'asset
            
        Returns:
            True si ajouté avec succès
        """
        try:
            self.assets[asset_id] = {
                "name": asset_data.get("name", asset_id),
                "type": asset_data.get("type", "system"),
                "position": asset_data.get("position", (0, 0, 0)),
                "size": asset_data.get("size", 5),
                "color": asset_data.get("color", "#CCCCCC"),
                "importance": asset_data.get("importance", "normal"),
                "status": asset_data.get("status", "active"),
                "created_at": datetime.now().isoformat()
            }
            
            logger.info(f"Asset ajouté à StarMap: {asset_id}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur ajout asset StarMap: {e}")
            return False
    
    def update_threat_position(self, threat_id: str) -> bool:
        """Met à jour la position d'une menace basée sur sa vélocité."""
        try:
            if threat_id not in self.threats:
                return False
            
            threat = self.threats[threat_id]
            
            # Mise à jour de la position
            new_x = threat.position[0] + threat.velocity[0]
            new_y = threat.position[1] + threat.velocity[1]
            new_z = threat.position[2] + threat.velocity[2]
            
            # Limitation aux bornes
            new_x = max(self.scene_bounds[0], min(self.scene_bounds[1], new_x))
            new_y = max(self.scene_bounds[2], min(self.scene_bounds[3], new_y))
            new_z = max(self.scene_bounds[4], min(self.scene_bounds[5], new_z))
            
            threat.position = (new_x, new_y, new_z)
            threat.last_update = datetime.now()
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur mise à jour position menace: {e}")
            return False
    
    def detect_threat_defense_interactions(self) -> List[Dict]:
        """Détecte les interactions entre menaces et défenses."""
        interactions = []
        
        try:
            for threat_id, threat in self.threats.items():
                for defense_id, defense in self.defenses.items():
                    if not defense.active:
                        continue
                    
                    # Calcul de la distance
                    dx = threat.position[0] - defense.position[0]
                    dy = threat.position[1] - defense.position[1]
                    dz = threat.position[2] - defense.position[2]
                    distance = math.sqrt(dx*dx + dy*dy + dz*dz)
                    
                    # Vérification si dans le rayon de protection
                    if distance <= defense.radius:
                        interaction = {
                            "threat_id": threat_id,
                            "defense_id": defense_id,
                            "distance": distance,
                            "interaction_type": "within_range",
                            "timestamp": datetime.now().isoformat(),
                            "threat_severity": threat.severity,
                            "defense_strength": defense.strength
                        }
                        
                        # Calcul de l'efficacité de la défense
                        effectiveness = min(1.0, defense.strength / self._get_threat_power(threat))
                        interaction["effectiveness"] = effectiveness
                        
                        interactions.append(interaction)
                        
                        # Action de défense si efficace
                        if effectiveness > 0.7:
                            self._trigger_defense_action(threat_id, defense_id, effectiveness)
            
        except Exception as e:
            logger.error(f"Erreur détection interactions: {e}")
        
        return interactions
    
    def _get_threat_power(self, threat: ThreatObject3D) -> float:
        """Calcule la puissance d'une menace."""
        power_mapping = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0
        }
        return power_mapping.get(threat.severity, 5.0)
    
    def _trigger_defense_action(self, threat_id: str, defense_id: str, effectiveness: float):
        """Déclenche une action de défense."""
        try:
            action = {
                "threat_id": threat_id,
                "defense_id": defense_id,
                "action": "blocked" if effectiveness > 0.9 else "mitigated",
                "effectiveness": effectiveness,
                "timestamp": datetime.now().isoformat()
            }
            
            self.defense_activities.append(action)
            
            # Si très efficace, suppression de la menace
            if effectiveness > 0.9 and threat_id in self.threats:
                del self.threats[threat_id]
                logger.info(f"Menace {threat_id} bloquée par {defense_id}")
            
        except Exception as e:
            logger.error(f"Erreur action défense: {e}")
    
    def start_animation(self):
        """Démarre l'animation 3D."""
        if not self.animation_active:
            self.animation_active = True
            self.animation_thread = threading.Thread(target=self._animation_loop, daemon=True)
            self.animation_thread.start()
            logger.info("Animation StarMap démarrée")
    
    def stop_animation(self):
        """Arrête l'animation 3D."""
        self.animation_active = False
        if self.animation_thread and self.animation_thread.is_alive():
            self.animation_thread.join(timeout=2)
        logger.info("Animation StarMap arrêtée")
    
    def _animation_loop(self):
        """Boucle principale d'animation."""
        while self.animation_active:
            try:
                # Mise à jour des positions des menaces
                for threat_id in list(self.threats.keys()):
                    self.update_threat_position(threat_id)
                
                # Détection des interactions
                interactions = self.detect_threat_defense_interactions()
                
                # Nettoyage des anciennes menaces
                self._cleanup_old_threats()
                
                # Pause basée sur le taux de rafraîchissement
                time.sleep(1.0 / self.config["refresh_rate"])
                
            except Exception as e:
                logger.error(f"Erreur boucle animation: {e}")
                time.sleep(1)
    
    def _cleanup_old_threats(self):
        """Nettoie les anciennes menaces."""
        try:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(minutes=10)  # Suppression après 10 minutes
            
            old_threats = [
                threat_id for threat_id, threat in self.threats.items()
                if threat.created_at < cutoff_time
            ]
            
            for threat_id in old_threats:
                del self.threats[threat_id]
                logger.debug(f"Menace expirée supprimée: {threat_id}")
                
        except Exception as e:
            logger.error(f"Erreur nettoyage menaces: {e}")
    
    def generate_3d_plot(self, output_format: str = "html") -> Optional[str]:
        """
        Génère un plot 3D de la scène actuelle.
        
        Args:
            output_format: Format de sortie (html, png, json)
            
        Returns:
            Chemin du fichier généré ou None
        """
        try:
            if not plotly_available:
                logger.warning("Plotly non disponible - utilisation de matplotlib")
                return self._generate_matplotlib_plot()
            
            return self._generate_plotly_plot(output_format)
            
        except Exception as e:
            logger.error(f"Erreur génération plot 3D: {e}")
            return None
    
    def _generate_plotly_plot(self, output_format: str) -> Optional[str]:
        """Génère un plot 3D avec Plotly."""
        try:
            fig = go.Figure()
            
            # Ajout des assets
            if self.assets:
                asset_x, asset_y, asset_z = [], [], []
                asset_names, asset_colors, asset_sizes = [], [], []
                
                for asset_id, asset in self.assets.items():
                    pos = asset["position"]
                    asset_x.append(pos[0])
                    asset_y.append(pos[1])
                    asset_z.append(pos[2])
                    asset_names.append(asset["name"])
                    asset_colors.append(asset["color"])
                    asset_sizes.append(asset["size"])
                
                fig.add_trace(go.Scatter3d(
                    x=asset_x, y=asset_y, z=asset_z,
                    mode='markers',
                    marker=dict(
                        size=asset_sizes,
                        color=asset_colors,
                        opacity=0.8
                    ),
                    text=asset_names,
                    name="Assets",
                    hovertemplate="<b>%{text}</b><br>Position: (%{x}, %{y}, %{z})<extra></extra>"
                ))
            
            # Ajout des menaces
            if self.threats:
                threat_x, threat_y, threat_z = [], [], []
                threat_names, threat_colors, threat_sizes = [], [], []
                
                for threat_id, threat in self.threats.items():
                    pos = threat.position
                    threat_x.append(pos[0])
                    threat_y.append(pos[1])
                    threat_z.append(pos[2])
                    threat_names.append(f"{threat.threat_type} ({threat.severity})")
                    threat_colors.append(threat.color)
                    threat_sizes.append(threat.size)
                
                fig.add_trace(go.Scatter3d(
                    x=threat_x, y=threat_y, z=threat_z,
                    mode='markers',
                    marker=dict(
                        size=threat_sizes,
                        color=threat_colors,
                        opacity=0.7,
                        symbol='diamond'
                    ),
                    text=threat_names,
                    name="Threats",
                    hovertemplate="<b>%{text}</b><br>Position: (%{x}, %{y}, %{z})<extra></extra>"
                ))
            
            # Ajout des défenses
            if self.defenses:
                defense_x, defense_y, defense_z = [], [], []
                defense_names, defense_colors, defense_sizes = [], [], []
                
                for defense_id, defense in self.defenses.items():
                    pos = defense.position
                    defense_x.append(pos[0])
                    defense_y.append(pos[1])
                    defense_z.append(pos[2])
                    defense_names.append(f"{defense.defense_type} (Force: {defense.strength})")
                    defense_colors.append(defense.color)
                    defense_sizes.append(max(8, defense.radius / 2))
                
                fig.add_trace(go.Scatter3d(
                    x=defense_x, y=defense_y, z=defense_z,
                    mode='markers',
                    marker=dict(
                        size=defense_sizes,
                        color=defense_colors,
                        opacity=0.6,
                        symbol='square'
                    ),
                    text=defense_names,
                    name="Defenses",
                    hovertemplate="<b>%{text}</b><br>Position: (%{x}, %{y}, %{z})<extra></extra>"
                ))
            
            # Configuration de la scène
            fig.update_layout(
                title="StarMap Threat Visualizer - Projet Andromède",
                scene=dict(
                    xaxis_title="X Axis",
                    yaxis_title="Y Axis", 
                    zaxis_title="Z Axis",
                    bgcolor="black" if self.config["theme"] == "dark" else "white",
                    camera=dict(
                        eye=dict(x=1.5, y=1.5, z=1.5)
                    )
                ),
                template="plotly_dark" if self.config["theme"] == "dark" else "plotly_white"
            )
            
            # Sauvegarde
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"starmap_{timestamp}.{output_format}"
            
            if output_format == "html":
                fig.write_html(filename)
            elif output_format == "png":
                fig.write_image(filename)
            elif output_format == "json":
                with open(filename, 'w') as f:
                    json.dump(fig.to_dict(), f)
            
            logger.info(f"Plot 3D généré: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Erreur génération Plotly: {e}")
            return None
    
    def _generate_matplotlib_plot(self) -> Optional[str]:
        """Génère un plot 3D avec Matplotlib (fallback)."""
        try:
            if not matplotlib_available:
                logger.error("Matplotlib non disponible")
                return None
            
            fig = plt.figure(figsize=(12, 8))
            ax = fig.add_subplot(111, projection='3d')
            
            # Assets
            for asset_id, asset in self.assets.items():
                pos = asset["position"]
                ax.scatter(pos[0], pos[1], pos[2], 
                          s=asset["size"]*20, c=asset["color"], 
                          marker='o', alpha=0.8, label=f"Asset: {asset['name']}")
            
            # Menaces
            for threat_id, threat in self.threats.items():
                pos = threat.position
                ax.scatter(pos[0], pos[1], pos[2],
                          s=threat.size*30, c=threat.color,
                          marker='^', alpha=0.7, label=f"Threat: {threat.threat_type}")
            
            # Défenses
            for defense_id, defense in self.defenses.items():
                pos = defense.position
                ax.scatter(pos[0], pos[1], pos[2],
                          s=defense.radius*10, c=defense.color,
                          marker='s', alpha=0.6, label=f"Defense: {defense.defense_type}")
            
            ax.set_xlabel('X Axis')
            ax.set_ylabel('Y Axis')
            ax.set_zlabel('Z Axis')
            ax.set_title('StarMap Threat Visualizer - Matplotlib View')
            
            # Sauvegarde
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"starmap_matplotlib_{timestamp}.png"
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Plot Matplotlib généré: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Erreur génération Matplotlib: {e}")
            return None
    
    def get_scene_statistics(self) -> Dict:
        """Retourne les statistiques de la scène 3D."""
        return {
            "threats_count": len(self.threats),
            "defenses_count": len(self.defenses),
            "assets_count": len(self.assets),
            "threat_by_severity": self._count_threats_by_severity(),
            "defense_by_type": self._count_defenses_by_type(),
            "active_interactions": len(self.detect_threat_defense_interactions()),
            "animation_active": self.animation_active,
            "last_render": self.last_render_time.isoformat()
        }
    
    def _count_threats_by_severity(self) -> Dict[str, int]:
        """Compte les menaces par sévérité."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for threat in self.threats.values():
            counts[threat.severity] = counts.get(threat.severity, 0) + 1
        return counts
    
    def _count_defenses_by_type(self) -> Dict[str, int]:
        """Compte les défenses par type."""
        counts = {}
        for defense in self.defenses.values():
            counts[defense.defense_type] = counts.get(defense.defense_type, 0) + 1
        return counts
    
    def export_scene_data(self) -> Dict:
        """Exporte les données de la scène pour sauvegarde."""
        return {
            "timestamp": datetime.now().isoformat(),
            "threats": {tid: {
                "threat_id": t.threat_id,
                "threat_type": t.threat_type,
                "position": t.position,
                "severity": t.severity,
                "size": t.size,
                "color": t.color,
                "velocity": t.velocity,
                "metadata": t.metadata
            } for tid, t in self.threats.items()},
            "defenses": {did: {
                "defense_id": d.defense_id,
                "defense_type": d.defense_type,
                "position": d.position,
                "strength": d.strength,
                "radius": d.radius,
                "color": d.color,
                "active": d.active,
                "metadata": d.metadata
            } for did, d in self.defenses.items()},
            "assets": self.assets,
            "config": self.config
        }
    
    def clear_scene(self):
        """Efface tous les objets de la scène."""
        self.threats.clear()
        self.defenses.clear()
        self.assets.clear()
        self.threat_history.clear()
        self.attack_vectors.clear()
        self.defense_activities.clear()
        logger.info("Scène StarMap effacée")
    
    def get_status(self) -> Dict:
        """Retourne le statut du visualiseur."""
        return {
            "status": self.status,
            "animation_active": self.animation_active,
            "plotly_available": plotly_available,
            "matplotlib_available": matplotlib_available,
            "objects_count": len(self.threats) + len(self.defenses) + len(self.assets)
        } 

    def get_stats(self) -> Dict:
        """Retourne les statistiques de la visualisation."""
        try:
            return {
                "total_threats": len(self.threats),
                "total_defenses": len(self.defenses),
                "active_threats": len([t for t in self.threats.values() if t.get("status") == "active"]),
                "threat_types": list(set(t.get("type", "unknown") for t in self.threats.values())),
                "last_update": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Erreur stats visualisation: {e}")
            return {"total_threats": 0, "total_defenses": 0, "error": str(e)} 