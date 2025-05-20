#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Scanner CSV pour la détection de cybermenaces
Module principal qui coordonne l'analyse des fichiers CSV et la génération de rapports.
"""

import os
import sys
import csv
import json
import datetime
import hashlib
from pathlib import Path

# Chemins relatifs pour les différents composants
RULES_DIR = Path(__file__).parent.parent / "rules"
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
STATIC_DIR = Path(__file__).parent.parent / "static"

# Constantes pour le scoring
SCORE_CRITICAL = 90
SCORE_HIGH = 70
SCORE_MEDIUM = 50
SCORE_LOW = 30
SCORE_INFO = 10

class CSVScanner:
    """
    Scanner principal pour l'analyse des fichiers CSV à la recherche de menaces potentielles.
    """
    
    def __init__(self):
        """Initialise le scanner avec les règles par défaut."""
        self.rules = self._load_rules()
        self.results = []
        self.total_score = 0
        self.file_hash = ""
        self.scan_date = datetime.datetime.now()
        
    def _load_rules(self):
        """Charge les règles YARA et les patterns de détection depuis le dossier rules."""
        rules = []
        
        # Chargement des règles depuis le fichier JSON
        rules_file = RULES_DIR / "csv_rules.json"
        if rules_file.exists():
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)
        else:
            # Règles par défaut si le fichier n'existe pas
            rules = [
                {
                    "name": "Détection BitLocker",
                    "description": "Détecte les mentions de BitLocker qui pourraient indiquer un chiffrement malveillant",
                    "pattern": "bitlocker",
                    "severity": "high",
                    "score": SCORE_HIGH
                },
                {
                    "name": "Détection Ransomware",
                    "description": "Détecte les mentions de ransomware connus",
                    "pattern": "ransomware|wannacry|ryuk|lockbit|revil",
                    "severity": "critical",
                    "score": SCORE_CRITICAL
                },
                {
                    "name": "Extensions suspectes",
                    "description": "Détecte les extensions de fichiers potentiellement malveillantes",
                    "pattern": "\\.exe|\\.dll|\\.bat|\\.ps1|\\.vbs|\\.js|\\.hta",
                    "severity": "medium",
                    "score": SCORE_MEDIUM
                },
                {
                    "name": "Commandes PowerShell suspectes",
                    "description": "Détecte les commandes PowerShell potentiellement malveillantes",
                    "pattern": "invoke-expression|iex|invoke-webrequest|downloadstring|hidden|bypass|encodedcommand",
                    "severity": "high",
                    "score": SCORE_HIGH
                },
                {
                    "name": "URLs suspectes",
                    "description": "Détecte les URLs potentiellement malveillantes",
                    "pattern": "http://|https://|ftp://|pastebin|github|raw|download",
                    "severity": "medium",
                    "score": SCORE_MEDIUM
                }
            ]
            
            # Création du dossier rules s'il n'existe pas
            os.makedirs(RULES_DIR, exist_ok=True)
            
            # Sauvegarde des règles par défaut
            with open(rules_file, 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=4)
                
        return rules
    
    def scan_file(self, file_path):
        """
        Analyse un fichier CSV à la recherche de menaces potentielles.
        
        Args:
            file_path (str): Chemin vers le fichier CSV à analyser
            
        Returns:
            dict: Résultats de l'analyse
        """
        self.results = []
        self.total_score = 0
        self.file_path = file_path
        self.file_hash = self._calculate_file_hash(file_path)
        self.scan_date = datetime.datetime.now()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                csv_reader = csv.reader(f)
                headers = next(csv_reader, [])
                
                # Analyse des en-têtes
                for rule in self.rules:
                    for header in headers:
                        if self._check_pattern(header, rule["pattern"]):
                            self._add_result(rule, header, "En-tête")
                
                # Analyse des données
                for row_num, row in enumerate(csv_reader, 1):
                    for col_num, cell in enumerate(row):
                        for rule in self.rules:
                            if self._check_pattern(cell, rule["pattern"]):
                                self._add_result(rule, cell, f"Ligne {row_num}, Colonne {col_num+1}")
        
        except Exception as e:
            self.results.append({
                "rule_name": "Erreur d'analyse",
                "description": f"Une erreur s'est produite lors de l'analyse: {str(e)}",
                "match": str(e),
                "location": "N/A",
                "severity": "error",
                "score": 0
            })
        
        return self._get_report()
    
    def _check_pattern(self, text, pattern):
        """Vérifie si un pattern est présent dans le texte (version simplifiée sans regex)."""
        if not text or not pattern:
            return False
            
        text = text.lower()
        
        # Gestion des patterns avec alternatives (a|b|c)
        if "|" in pattern:
            patterns = pattern.split("|")
            return any(p.lower() in text for p in patterns)
        
        return pattern.lower() in text
    
    def _add_result(self, rule, match, location):
        """Ajoute un résultat à la liste des détections."""
        result = {
            "rule_name": rule["name"],
            "description": rule["description"],
            "match": match,
            "location": location,
            "severity": rule["severity"],
            "score": rule["score"]
        }
        
        self.results.append(result)
        self.total_score += rule["score"]
    
    def _calculate_file_hash(self, file_path):
        """Calcule le hash SHA-256 du fichier."""
        sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return "Impossible de calculer le hash"
    
    def _get_report(self):
        """Génère un rapport complet de l'analyse."""
        # Détermination du niveau de risque global
        risk_level = "Inconnu"
        if self.total_score >= SCORE_CRITICAL:
            risk_level = "Critique"
        elif self.total_score >= SCORE_HIGH:
            risk_level = "Élevé"
        elif self.total_score >= SCORE_MEDIUM:
            risk_level = "Moyen"
        elif self.total_score >= SCORE_LOW:
            risk_level = "Faible"
        elif self.total_score > 0:
            risk_level = "Informatif"
        else:
            risk_level = "Aucun risque détecté"
        
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "scan_date": self.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
            "total_score": self.total_score,
            "risk_level": risk_level,
            "results": self.results
        }
    
    def generate_html_report(self, report, output_path=None):
        """
        Génère un rapport HTML à partir des résultats de l'analyse.
        
        Args:
            report (dict): Résultats de l'analyse
            output_path (str, optional): Chemin de sortie pour le rapport HTML
            
        Returns:
            str: Chemin vers le rapport HTML généré
        """
        # Création du dossier templates s'il n'existe pas
        os.makedirs(TEMPLATES_DIR, exist_ok=True)
        
        # Création du dossier static s'il n'existe pas
        os.makedirs(STATIC_DIR, exist_ok=True)
        
        # Création du fichier CSS s'il n'existe pas
        css_file = STATIC_DIR / "style.css"
        if not css_file.exists():
            with open(css_file, 'w', encoding='utf-8') as f:
                f.write("""
                :root {
                    --color-primary: #3498db;
                    --color-secondary: #2c3e50;
                    --color-background: #f8f9fa;
                    --color-text: #333;
                    --color-critical: #e74c3c;
                    --color-high: #e67e22;
                    --color-medium: #f39c12;
                    --color-low: #3498db;
                    --color-info: #2ecc71;
                }
                
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: var(--color-text);
                    background-color: var(--color-background);
                    margin: 0;
                    padding: 20px;
                }
                
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                }
                
                header {
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 1px solid #eee;
                }
                
                h1 {
                    color: var(--color-secondary);
                    margin-bottom: 10px;
                }
                
                .summary {
                    display: flex;
                    justify-content: space-between;
                    flex-wrap: wrap;
                    margin-bottom: 30px;
                    gap: 20px;
                }
                
                .summary-item {
                    flex: 1;
                    min-width: 200px;
                    padding: 15px;
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                }
                
                .summary-item h3 {
                    margin-top: 0;
                    color: var(--color-secondary);
                    font-size: 16px;
                }
                
                .summary-item p {
                    margin-bottom: 0;
                    font-size: 18px;
                    font-weight: 600;
                }
                
                .risk-level {
                    font-weight: bold;
                    padding: 5px 10px;
                    border-radius: 4px;
                    display: inline-block;
                }
                
                .risk-critical {
                    background-color: var(--color-critical);
                    color: white;
                }
                
                .risk-high {
                    background-color: var(--color-high);
                    color: white;
                }
                
                .risk-medium {
                    background-color: var(--color-medium);
                    color: white;
                }
                
                .risk-low {
                    background-color: var(--color-low);
                    color: white;
                }
                
                .risk-info {
                    background-color: var(--color-info);
                    color: white;
                }
                
                .results {
                    margin-top: 30px;
                }
                
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                }
                
                th, td {
                    padding: 12px 15px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                
                th {
                    background-color: var(--color-secondary);
                    color: white;
                    font-weight: 600;
                }
                
                tr:nth-child(even) {
                    background-color: #f8f9fa;
                }
                
                tr:hover {
                    background-color: #f1f1f1;
                }
                
                .severity {
                    font-weight: bold;
                    padding: 3px 8px;
                    border-radius: 4px;
                    display: inline-block;
                    text-transform: capitalize;
                }
                
                .severity-critical {
                    background-color: var(--color-critical);
                    color: white;
                }
                
                .severity-high {
                    background-color: var(--color-high);
                    color: white;
                }
                
                .severity-medium {
                    background-color: var(--color-medium);
                    color: white;
                }
                
                .severity-low {
                    background-color: var(--color-low);
                    color: white;
                }
                
                .severity-info {
                    background-color: var(--color-info);
                    color: white;
                }
                
                footer {
                    margin-top: 40px;
                    text-align: center;
                    color: #777;
                    font-size: 14px;
                }
                
                .match {
                    font-family: monospace;
                    background-color: #f8f9fa;
                    padding: 2px 5px;
                    border-radius: 3px;
                    border: 1px solid #ddd;
                    word-break: break-all;
                }
                
                @media (max-width: 768px) {
                    .container {
                        padding: 15px;
                    }
                    
                    .summary {
                        flex-direction: column;
                    }
                    
                    table {
                        display: block;
                        overflow-x: auto;
                    }
                }
                """)
        
        # Génération du rapport HTML
        if output_path is None:
            output_dir = Path(report["file_path"]).parent
            output_filename = f"rapport_scan_{Path(report['file_path']).stem}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            output_path = output_dir / output_filename
        
        # Génération du contenu HTML
        html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'analyse - Projet Andromède</title>
    <link rel="stylesheet" href="{css_file}">
    <style>
        /* Styles intégrés au cas où le fichier CSS ne serait pas accessible */
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); }}
        header {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #eee; }}
        h1 {{ color: #2c3e50; margin-bottom: 10px; }}
        .risk-level {{ font-weight: bold; padding: 5px 10px; border-radius: 4px; display: inline-block; }}
        .risk-critical {{ background-color: #e74c3c; color: white; }}
        .risk-high {{ background-color: #e67e22; color: white; }}
        .risk-medium {{ background-color: #f39c12; color: white; }}
        .risk-low {{ background-color: #3498db; color: white; }}
        .risk-info {{ background-color: #2ecc71; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #2c3e50; color: white; }}
        .severity {{ font-weight: bold; padding: 3px 8px; border-radius: 4px; display: inline-block; text-transform: capitalize; }}
        .severity-critical {{ background-color: #e74c3c; color: white; }}
        .severity-high {{ background-color: #e67e22; color: white; }}
        .severity-medium {{ background-color: #f39c12; color: white; }}
        .severity-low {{ background-color: #3498db; color: white; }}
        .severity-info {{ background-color: #2ecc71; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Rapport d'analyse de sécurité - Projet Andromède</h1>
            <p>Analyse de fichier CSV pour la détection de cybermenaces</p>
        </header>
        
        <div class="summary">
            <div class="summary-item">
                <h3>Fichier analysé</h3>
                <p>{Path(report["file_path"]).name}</p>
            </div>
            <div class="summary-item">
                <h3>Date d'analyse</h3>
                <p>{report["scan_date"]}</p>
            </div>
            <div class="summary-item">
                <h3>Score de risque</h3>
                <p>{report["total_score"]}</p>
            </div>
            <div class="summary-item">
                <h3>Niveau de risque</h3>
                <p class="risk-level risk-{report["risk_level"].lower()}">{report["risk_level"]}</p>
            </div>
        </div>
        
        <div class="file-info">
            <h2>Informations sur le fichier</h2>
            <table>
                <tr>
                    <th>Chemin du fichier</th>
                    <td>{report["file_path"]}</td>
                </tr>
                <tr>
                    <th>Hash SHA-256</th>
                    <td>{report["file_hash"]}</td>
                </tr>
            </table>
        </div>
        
        <div class="results">
            <h2>Résultats de l'analyse</h2>"""
            
        # Ajout conditionnel des résultats
        if not report["results"]:
            html_content += """
            <p>Aucune menace détectée.</p>"""
        else:
            html_content += """
            <table>
                <thead>
                    <tr>
                        <th>Règle</th>
                        <th>Description</th>
                        <th>Correspondance</th>
                        <th>Emplacement</th>
                        <th>Sévérité</th>
                        <th>Score</th>
                    </tr>
                </thead>
                <tbody>"""
                
            # Ajout des lignes de résultats
            for result in report["results"]:
                html_content += f"""
                    <tr>
                        <td>{result["rule_name"]}</td>
                        <td>{result["description"]}</td>
                        <td><span class="match">{result["match"]}</span></td>
                        <td>{result["location"]}</td>
                        <td><span class="severity severity-{result["severity"]}">{result["severity"]}</span></td>
                        <td>{result["score"]}</td>
                    </tr>"""
                    
            html_content += """
                </tbody>
            </table>"""
            
        # Fin du document HTML
        html_content += f"""
        </div>
        
        <footer>
            <p>Généré par Projet Andromède - Antivirus Next-Gen inspiré par la défense de la galaxie d'Andromède</p>
            <p>© {datetime.datetime.now().year} Projet Andromède</p>
        </footer>
    </div>
</body>
</html>
"""
        
        # Écriture du contenu dans le fichier
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)

def main():
    """Fonction principale pour l'exécution du scanner en ligne de commande."""
    if len(sys.argv) < 2:
        print("Usage: python main.py <chemin_vers_fichier_csv>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(f"Erreur: Le fichier {file_path} n'existe pas.")
        sys.exit(1)
    
    if not file_path.lower().endswith('.csv'):
        print(f"Erreur: Le fichier {file_path} n'est pas un fichier CSV.")
        sys.exit(1)
    
    scanner = CSVScanner()
    print(f"Analyse du fichier {file_path}...")
    
    report = scanner.scan_file(file_path)
    
    print(f"\nRésultats de l'analyse:")
    print(f"Niveau de risque: {report['risk_level']} (Score: {report['total_score']})")
    print(f"Nombre de détections: {len(report['results'])}")
    
    if report['results']:
        print("\nDétections:")
        for i, result in enumerate(report['results'], 1):
            print(f"{i}. {result['rule_name']} ({result['severity']}) - {result['match']} à {result['location']}")
    
    # Génération du rapport HTML
    html_report = scanner.generate_html_report(report)
    print(f"\nRapport HTML généré: {html_report}")

if __name__ == "__main__":
    main()
