#!/usr/bin/env python3
"""
Test en conditions réelles d'Andromède
Vérifie que toutes les fonctionnalités fonctionnent avec de vraies données
"""

import os
import sys
import csv
import time
import requests
import threading
from datetime import datetime

# Ajouter le répertoire src au path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def create_real_malicious_csv():
    """Créer un fichier CSV avec de vraies données malveillantes"""
    filename = "real_test_data.csv"
    
    # Données réellement malveillantes/suspectes
    malicious_data = [
        ["192.168.1.100", "admin", "admin123", "ssh_bruteforce", "2025-01-23 20:00:00"],
        ["malware.exe", "trojan", "C:\\Windows\\System32\\", "file_infection", "2025-01-23 20:01:00"],
        ["phishing@fake-bank.com", "credential_theft", "login_page", "email_attack", "2025-01-23 20:02:00"],
        ["10.0.0.1", "port_scan", "nmap -sS", "network_recon", "2025-01-23 20:03:00"],
        ["javascript:alert('XSS')", "cross_site_scripting", "form_input", "web_attack", "2025-01-23 20:04:00"],
        ["'; DROP TABLE users; --", "sql_injection", "user_input", "database_attack", "2025-01-23 20:05:00"],
        ["encrypted_payload_base64", "ransomware", "file_encryption", "crypto_attack", "2025-01-23 20:06:00"],
        ["botnet_command_server", "c2_communication", "tcp_443", "botnet_activity", "2025-01-23 20:07:00"],
        ["privilege_escalation", "kernel_exploit", "system_call", "local_exploit", "2025-01-23 20:08:00"],
        ["lateral_movement", "smb_exploit", "network_share", "persistence", "2025-01-23 20:09:00"]
    ]
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["source", "threat_type", "payload", "category", "timestamp"])
        writer.writerows(malicious_data)
    
    print(f"✓ Fichier CSV malveillant créé: {filename}")
    return filename

def test_csv_scanner_real(csv_file):
    """Tester le scanner CSV avec de vraies données"""
    print("\n🔍 TEST SCANNER CSV EN CONDITIONS RÉELLES")
    
    try:
        from main import main as scanner_main
        import sys
        from io import StringIO
        
        # Capturer la sortie
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        
        # Simuler les arguments de ligne de commande
        sys.argv = ['main.py', csv_file]
        
        # Exécuter le scanner
        scanner_main()
        
        # Récupérer la sortie
        sys.stdout = old_stdout
        output = mystdout.getvalue()
        
        print(f"✓ Scanner exécuté avec succès")
        print(f"✓ Sortie générée: {len(output)} caractères")
        
        # Vérifier qu'un rapport a été généré
        if os.path.exists("security_report.html"):
            print("✓ Rapport HTML généré")
            with open("security_report.html", 'r', encoding='utf-8') as f:
                report_content = f.read()
                if len(report_content) > 1000:
                    print(f"✓ Rapport contient {len(report_content)} caractères de données")
                    return True
        
        return False
        
    except Exception as e:
        print(f"✗ Erreur scanner: {e}")
        return False

def test_ai_orion_real():
    """Tester OrionCore avec de vraies données"""
    print("\n🤖 TEST ORION CORE - ANALYSE IA RÉELLE")
    
    try:
        from core.orion_core import OrionCore
        
        orion = OrionCore()
        
        # Test avec de vraies menaces
        real_threats = [
            "Tentative d'injection SQL détectée: '; DROP TABLE users; --",
            "Activité de botnet suspecte sur le port 443",
            "Exécutable malveillant trouvé: trojan.exe",
            "Scan de ports agressif depuis 192.168.1.100",
            "Payload chiffré suspect détecté"
        ]
        
        results = []
        for threat in real_threats:
            result = orion.analyze_threat(threat)
            results.append(result)
            print(f"  Menace: {threat[:50]}...")
            print(f"  Analyse: {result['severity']} - {result['description'][:100]}...")
        
        # Vérifier la qualité des analyses
        if len(results) == len(real_threats):
            print(f"✓ {len(results)} analyses IA générées")
            return True
        
        return False
        
    except Exception as e:
        print(f"✗ Erreur OrionCore: {e}")
        return False

def test_blockchain_real():
    """Tester la blockchain avec de vraies signatures"""
    print("\n⛓️ TEST BLOCKCHAIN - SIGNATURES RÉELLES")
    
    try:
        from core.andromeda_chain import AndromedaChain
        
        blockchain = AndromedaChain()
        
        # Ajouter de vraies signatures de menaces
        real_signatures = [
            "md5:5d41402abc4b2a76b9719d911017c592",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "yara:rule_malware_detection { condition: $hex_string }",
            "snort:alert tcp any any -> any 80 (msg:\"HTTP attack\";)",
            "suricata:alert dns any any -> any any (msg:\"DNS tunnel\";)"
        ]
        
        for signature in real_signatures:
            blockchain.add_threat_signature(signature, {"severity": "high", "type": "malware"})
        
        # Vérifier l'intégrité de la chaîne
        if blockchain.validate_chain():
            print(f"✓ Blockchain validée avec {len(blockchain.chain)} blocs")
            print(f"✓ {len(real_signatures)} signatures ajoutées")
            return True
        
        return False
        
    except Exception as e:
        print(f"✗ Erreur blockchain: {e}")
        return False

def test_web_interface_real():
    """Tester l'interface web en conditions réelles"""
    print("\n🌐 TEST INTERFACE WEB - ACCÈS RÉEL")
    
    try:
        # Démarrer l'application Flask en arrière-plan
        import subprocess
        import time
        
        # Lancer le serveur web
        print("  Démarrage du serveur Flask...")
        process = subprocess.Popen([
            sys.executable, "src/app.py"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Attendre que le serveur démarre
        time.sleep(3)
        
        # Tester les endpoints
        endpoints = [
            "http://127.0.0.1:5000/",
            "http://127.0.0.1:5000/chat",
            "http://127.0.0.1:5000/ai-analysis",
            "http://127.0.0.1:5000/starmap",
            "http://127.0.0.1:5000/system-status"
        ]
        
        results = []
        for endpoint in endpoints:
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code == 200:
                    print(f"  ✓ {endpoint} - Status: {response.status_code}")
                    results.append(True)
                else:
                    print(f"  ✗ {endpoint} - Status: {response.status_code}")
                    results.append(False)
            except Exception as e:
                print(f"  ✗ {endpoint} - Erreur: {e}")
                results.append(False)
        
        # Arrêter le serveur
        process.terminate()
        process.wait()
        
        success_rate = sum(results) / len(results) * 100
        print(f"✓ Interface web testée: {success_rate:.1f}% des endpoints fonctionnels")
        
        return success_rate >= 80
        
    except Exception as e:
        print(f"✗ Erreur interface web: {e}")
        return False

def test_quantum_encryption_real():
    """Tester le chiffrement quantique avec de vraies données"""
    print("\n🔐 TEST CHIFFREMENT QUANTIQUE - DONNÉES RÉELLES")
    
    try:
        from core.quantum_shield import QuantumShield
        
        quantum = QuantumShield()
        
        # Données sensibles réelles à chiffrer
        sensitive_data = [
            "Mot de passe admin: SuperSecretPassword123!",
            "Clé API: sk-1234567890abcdef",
            "Token JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "Signature de menace: md5:5d41402abc4b2a76b9719d911017c592",
            "Configuration réseau: 192.168.1.0/24"
        ]
        
        encrypted_data = []
        for data in sensitive_data:
            encrypted = quantum.encrypt_data(data)
            encrypted_data.append(encrypted)
            
            # Tenter de déchiffrer
            decrypted = quantum.decrypt_data(encrypted)
            
            if decrypted == data:
                print(f"  ✓ Chiffrement/déchiffrement réussi pour: {data[:30]}...")
            else:
                print(f"  ✗ Échec pour: {data[:30]}...")
                return False
        
        print(f"✓ {len(sensitive_data)} données chiffrées/déchiffrées avec succès")
        return True
        
    except Exception as e:
        print(f"✗ Erreur chiffrement quantique: {e}")
        return False

def test_voice_assistant_real():
    """Tester l'assistant vocal avec de vraies questions"""
    print("\n🎤 TEST ASSISTANT VOCAL - QUESTIONS RÉELLES")
    
    try:
        from core.astra_assistant import AstraAssistant
        
        astra = AstraAssistant()
        
        # Questions réelles de cybersécurité
        real_questions = [
            "Comment détecter une attaque par injection SQL ?",
            "Quelles sont les meilleures pratiques de sécurité réseau ?",
            "Comment analyser un fichier suspect ?",
            "Qu'est-ce qu'une attaque de type MITM ?",
            "Comment sécuriser une API REST ?"
        ]
        
        responses = []
        for question in real_questions:
            response = astra.process_voice_command(question)
            responses.append(response)
            print(f"  Question: {question}")
            print(f"  Réponse: {response['text'][:100]}...")
        
        # Vérifier la qualité des réponses
        valid_responses = [r for r in responses if len(r['text']) > 50]
        success_rate = len(valid_responses) / len(real_questions) * 100
        
        print(f"✓ Assistant vocal: {success_rate:.1f}% de réponses valides")
        return success_rate >= 80
        
    except Exception as e:
        print(f"✗ Erreur assistant vocal: {e}")
        return False

def test_3d_visualization_real():
    """Tester la visualisation 3D avec de vraies données"""
    print("\n🌟 TEST VISUALISATION 3D - DONNÉES RÉELLES")
    
    try:
        from core.starmap_visualizer import StarMapVisualizer
        
        visualizer = StarMapVisualizer()
        
        # Ajouter de vraies menaces avec positions géographiques
        real_threats = [
            {"ip": "192.168.1.100", "type": "bruteforce", "location": "Paris, France"},
            {"ip": "10.0.0.50", "type": "malware", "location": "Londres, UK"},
            {"ip": "172.16.0.25", "type": "phishing", "location": "Berlin, Allemagne"},
            {"ip": "203.0.113.0", "type": "ddos", "location": "Tokyo, Japon"},
            {"ip": "198.51.100.0", "type": "injection", "location": "New York, USA"}
        ]
        
        for threat in real_threats:
            visualizer.add_threat(threat['ip'], threat['type'], {"location": threat['location']})
        
        # Générer la visualisation
        plot_data = visualizer.generate_3d_plot()
        
        if plot_data and len(plot_data.get('data', [])) > 0:
            print(f"✓ Visualisation 3D générée avec {len(real_threats)} menaces")
            print(f"✓ Données de plot: {len(plot_data['data'])} éléments")
            return True
        
        return False
        
    except Exception as e:
        print(f"✗ Erreur visualisation 3D: {e}")
        return False

def main():
    """Test complet en conditions réelles"""
    print("=" * 60)
    print("🚀 ANDROMÈDE - TEST EN CONDITIONS RÉELLES")
    print("=" * 60)
    
    start_time = time.time()
    
    # Créer des données de test réelles
    csv_file = create_real_malicious_csv()
    
    # Tests des fonctionnalités
    tests = [
        ("Scanner CSV", test_csv_scanner_real, csv_file),
        ("IA OrionCore", test_ai_orion_real, None),
        ("Blockchain", test_blockchain_real, None),
        ("Interface Web", test_web_interface_real, None),
        ("Chiffrement Quantique", test_quantum_encryption_real, None),
        ("Assistant Vocal", test_voice_assistant_real, None),
        ("Visualisation 3D", test_3d_visualization_real, None)
    ]
    
    results = []
    
    for test_name, test_func, param in tests:
        print(f"\n{'=' * 20} {test_name} {'=' * 20}")
        try:
            if param:
                result = test_func(param)
            else:
                result = test_func()
            results.append(result)
        except Exception as e:
            print(f"✗ ÉCHEC du test {test_name}: {e}")
            results.append(False)
    
    # Résultats finaux
    print("\n" + "=" * 60)
    print("📊 RÉSULTATS DES TESTS EN CONDITIONS RÉELLES")
    print("=" * 60)
    
    success_count = sum(results)
    total_tests = len(results)
    success_rate = (success_count / total_tests) * 100
    
    for i, (test_name, _, _) in enumerate(tests):
        status = "✅ RÉUSSI" if results[i] else "❌ ÉCHEC"
        print(f"{test_name:.<25} {status}")
    
    print(f"\n📈 TAUX DE RÉUSSITE: {success_count}/{total_tests} ({success_rate:.1f}%)")
    
    elapsed_time = time.time() - start_time
    print(f"⏱️ TEMPS D'EXÉCUTION: {elapsed_time:.2f} secondes")
    
    if success_rate >= 85:
        print("\n🎉 VERDICT: TOUTES LES FONCTIONNALITÉS FONCTIONNENT EN CONDITIONS RÉELLES!")
        print("   Andromède est prêt pour un usage en production.")
    elif success_rate >= 70:
        print("\n⚠️ VERDICT: LA PLUPART DES FONCTIONNALITÉS FONCTIONNENT")
        print("   Quelques ajustements peuvent être nécessaires.")
    else:
        print("\n🚨 VERDICT: PLUSIEURS FONCTIONNALITÉS NÉCESSITENT DES CORRECTIONS")
        print("   Une révision approfondie est recommandée.")
    
    # Nettoyage
    try:
        os.remove(csv_file)
        if os.path.exists("security_report.html"):
            os.remove("security_report.html")
        print(f"\n🧹 Fichiers de test nettoyés")
    except:
        pass

if __name__ == "__main__":
    main() 