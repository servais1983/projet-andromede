#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Interface Web pour le scanner CSV
Ce script crée une interface web pour l'analyse des fichiers CSV.
"""

import os
import sys
import tempfile
from pathlib import Path
from flask import Flask, request, render_template, send_file, redirect, url_for, flash, jsonify

# Ajout du répertoire parent au path pour pouvoir importer main.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.main import CSVScanner

app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates'),
            static_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static'))

# Configuration
app.config['UPLOAD_FOLDER'] = os.path.join(tempfile.gettempdir(), 'andromede_uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max
app.secret_key = 'andromede_secret_key'

# Création du dossier d'upload s'il n'existe pas
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    """Page d'accueil avec formulaire d'upload."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Traitement de l'upload et analyse du fichier CSV."""
    if 'file' not in request.files:
        flash('Aucun fichier sélectionné')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('Aucun fichier sélectionné')
        return redirect(url_for('index'))
    
    if not file.filename.lower().endswith('.csv'):
        flash('Seuls les fichiers CSV sont acceptés')
        return redirect(url_for('index'))
    
    # Sauvegarde du fichier
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    
    # Analyse du fichier
    scanner = CSVScanner()
    report = scanner.scan_file(file_path)
    
    # Génération du rapport HTML
    report_path = scanner.generate_html_report(report)
    
    # Redirection vers la page de résultats
    return redirect(url_for('results', report=os.path.basename(report_path)))

@app.route('/results')
def results():
    """Affichage des résultats d'analyse."""
    report_name = request.args.get('report')
    if not report_name:
        flash('Rapport non trouvé')
        return redirect(url_for('index'))
    
    report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_name)
    if not os.path.exists(report_path):
        flash('Rapport non trouvé')
        return redirect(url_for('index'))
    
    return send_file(report_path)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API pour l'analyse des fichiers CSV."""
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400
    
    if not file.filename.lower().endswith('.csv'):
        return jsonify({'error': 'Seuls les fichiers CSV sont acceptés'}), 400
    
    # Sauvegarde du fichier
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    
    # Analyse du fichier
    scanner = CSVScanner()
    report = scanner.scan_file(file_path)
    
    # Retour des résultats en JSON
    return jsonify(report)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
