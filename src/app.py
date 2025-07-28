#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Projet Andromède - Interface Web pour le scanner CSV
Ce script crée une interface web pour l'analyse des fichiers CSV.
"""

import os
import sys
import tempfile
import json
from pathlib import Path
from flask import Flask, request, render_template, send_file, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
import pandas as pd
from datetime import datetime
import time

# Ajout du répertoire parent au path pour pouvoir importer main.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.main import CSVScanner

# Import des modules IA
try:
    from core.ai.astra_assistant import AstraAssistant
    from core.ai.orion_core import OrionCore
    from ui.starmap_visualizer import StarMapVisualizer
    AI_MODULES_AVAILABLE = True
except ImportError:
    AI_MODULES_AVAILABLE = False

app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates'),
            static_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static'))

# Configuration
app.config['UPLOAD_FOLDER'] = os.path.join(tempfile.gettempdir(), 'andromede_uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max
app.secret_key = 'andromede_secret_key_2025'

# Création du dossier d'upload s'il n'existe pas
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialisation des modules IA
astra_assistant = None
orion_core = None
starmap_visualizer = None

if AI_MODULES_AVAILABLE:
    try:
        astra_assistant = AstraAssistant()
        orion_core = OrionCore()
        starmap_visualizer = StarMapVisualizer()
        print("Modules IA initialises pour l'interface web")
    except Exception as e:
        print(f"Erreur initialisation IA web: {e}")

def allowed_file(filename):
    """Vérifie si le fichier est autorisé"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'csv'

@app.route('/')
def index():
    """Page d'accueil avec interface de téléchargement"""
    return render_template('index.html', 
                         astra_available=astra_assistant is not None,
                         ai_modules_status=get_ai_modules_status())

@app.route('/chat')
def chat():
    """Interface de chat avec l'assistant Astra"""
    return render_template('chat.html', 
                         astra_available=astra_assistant is not None,
                         project_name="Projet Andromède")

@app.route('/upload', methods=['POST'])
def upload_file():
    """API pour télécharger et analyser un fichier CSV"""
    try:
        # Vérifier qu'un fichier a été téléchargé
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Aucun fichier téléchargé'
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'Aucun fichier sélectionné'
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': 'Type de fichier non autorisé. Seuls les fichiers CSV sont acceptés.'
            }), 400
        
        # Sauvegarder le fichier
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Analyser le fichier
        start_time = time.time()
        scanner = CSVScanner()
        results = scanner.scan_file(file_path)
        
        # Analyse IA supplémentaire si disponible
        ai_insights = []
        if orion_core and results.get('results'):
            for result in results['results'][:5]:  # Limiter à 5 pour éviter la surcharge
                if result.get('match'):
                    try:
                        ai_analysis = orion_core.analyze_threat(result['match'])
                        ai_insights.append({
                            'threat': result['match'],
                            'ai_analysis': ai_analysis
                        })
                    except Exception as e:
                        print(f"Erreur analyse IA: {e}")
        
        # Générer le rapport HTML
        try:
            html_report_path = scanner.generate_html_report(results)
            report_url = f"/report/{os.path.basename(html_report_path)}"
        except Exception as e:
            print(f"Erreur génération rapport: {e}")
            html_report_path = None
            report_url = None
        
        # Calcul du temps de traitement
        processing_time = time.time() - start_time
        
        # Préparer la réponse
        response_data = {
            'success': True,
            'filename': file.filename,
            'threats_detected': len(results.get('results', [])),
            'risk_score': results.get('total_score', 0),
            'risk_level': results.get('risk_level', 'Inconnu'),
            'processing_time': round(processing_time, 2),
            'report_url': report_url,
            'ai_insights': ai_insights,
            'summary': {
                'total_rows_analyzed': results.get('rows_analyzed', 0),
                'threats_by_severity': categorize_threats_by_severity(results.get('results', [])),
                'top_threats': get_top_threats(results.get('results', []))
            }
        }
        
        # Nettoyage du fichier temporaire
        try:
            os.remove(file_path)
        except:
            pass
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Erreur lors du traitement: {e}")
        return jsonify({
            'success': False,
            'error': f'Erreur lors de l\'analyse: {str(e)}'
        }), 500

@app.route('/ai-analysis', methods=['POST'])
def ai_analysis():
    """API pour analyse IA directe"""
    if not astra_assistant:
        return jsonify({
            'success': False,
            'error': 'Assistant IA non disponible'
        }), 503
    
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        session_id = data.get('session_id', 'web_default')
        
        if not message:
            return jsonify({
                'success': False,
                'error': 'Message vide'
            }), 400
        
        # Conversation avec Astra
        response = astra_assistant.chat(message, session_id)
        
        return jsonify({
            'success': True,
            'response': response,
            'session_id': session_id,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Erreur IA: {str(e)}'
        }), 500

@app.route('/report/<filename>')
def serve_report(filename):
    """Servir les rapports HTML générés"""
    try:
        # Chercher le fichier dans le répertoire de travail
        report_path = os.path.join(os.getcwd(), filename)
        if os.path.exists(report_path):
            return send_file(report_path, as_attachment=False)
        
        # Chercher dans le dossier temporaire
        temp_report_path = os.path.join(tempfile.gettempdir(), filename)
        if os.path.exists(temp_report_path):
            return send_file(temp_report_path, as_attachment=False)
        
        return "Rapport non trouvé", 404
        
    except Exception as e:
        return f"Erreur lors du chargement du rapport: {e}", 500

@app.route('/status')
def system_status():
    """API pour obtenir le statut du système"""
    status = {
        'system': 'operational',
        'ai_modules': get_ai_modules_status(),
        'scanner': 'available',
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(status)

def get_ai_modules_status():
    """Obtient le statut des modules IA"""
    status = {}
    
    if astra_assistant:
        try:
            status['astra'] = astra_assistant.get_stats()
        except:
            status['astra'] = {'status': 'error'}
    else:
        status['astra'] = {'status': 'unavailable'}
    
    if orion_core:
        try:
            status['orion'] = orion_core.get_status()
        except:
            status['orion'] = {'status': 'error'}
    else:
        status['orion'] = {'status': 'unavailable'}
    
    if starmap_visualizer:
        status['starmap'] = {'status': 'available'}
    else:
        status['starmap'] = {'status': 'unavailable'}
    
    return status

def categorize_threats_by_severity(threats):
    """Catégorise les menaces par niveau de sévérité"""
    categories = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    for threat in threats:
        severity = threat.get('severity', 'info').lower()
        if severity in categories:
            categories[severity] += 1
        else:
            categories['info'] += 1
    
    return categories

def get_top_threats(threats):
    """Obtient les principales menaces détectées"""
    # Trier par score décroissant
    sorted_threats = sorted(threats, key=lambda x: x.get('score', 0), reverse=True)
    
    # Retourner les 5 principales
    top_threats = []
    for threat in sorted_threats[:5]:
        top_threats.append({
            'name': threat.get('rule_name', 'Menace inconnue'),
            'description': threat.get('description', ''),
            'severity': threat.get('severity', 'info'),
            'score': threat.get('score', 0),
            'location': threat.get('location', '')
        })
    
    return top_threats

@app.errorhandler(413)
def too_large(e):
    """Gestionnaire d'erreur pour fichiers trop volumineux"""
    return jsonify({
        'success': False,
        'error': 'Fichier trop volumineux. Taille maximale autorisée: 16 MB'
    }), 413

@app.errorhandler(500)
def internal_error(e):
    """Gestionnaire d'erreur interne"""
    return jsonify({
        'success': False,
        'error': 'Erreur interne du serveur'
    }), 500

if __name__ == '__main__':
    print("Demarrage de l'interface web Andromede...")
    print(f"Acces: http://localhost:5625")
    
    if AI_MODULES_AVAILABLE:
        print("Modules IA disponibles pour l'interface")
    else:
        print("Mode degrade - fonctionnalites de base disponibles")
    
    try:
        app.run(host='127.0.0.1', port=5625, debug=False, threaded=True)
    except Exception as e:
        print(f"Erreur demarrage serveur: {e}")
        print("   Verifiez que le port 5625 n'est pas deja utilise")
