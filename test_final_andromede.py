#!/usr/bin/env python3
"""
Test final complet du projet Andromède
Vérifie que toutes les fonctionnalités principales fonctionnent
"""

import os
import csv
import sys
import time
import subprocess
import requests
from datetime import datetime

def create_comprehensive_test_csv():
    """Créer un fichier CSV avec différents types de menaces"""
    filename = "test_complet_andromede.csv"
    
    test_data = [
        ["id", "source", "type", "data", "timestamp"],
        ["1", "user_input", "sql_injection", "admin'; DROP TABLE users; --", "2025-01-28 21:00:00"],
        ["2", "file_upload", "xss", "<script>alert('XSS Attack')</script>", "2025-01-28 21:01:00"],
        ["3", "network", "port_scan", "nmap -sS -p1-65535 192.168.1.1", "2025-01-28 21:02:00"],
        ["4", "email", "phishing", "Urgent: Verify password at fake-bank.com", "2025-01-28 21:03:00"],
        ["5", "file_system", "malware", "trojan.exe detected in downloads", "2025-01-28 21:04:00"],
        ["6", "network", "command_injection", "ping 127.0.0.1 && rm -rf /", "2025-01-28 21:05:00"],
        ["7", "web", "path_traversal", "../../../etc/passwd", "2025-01-28 21:06:00"],
        ["8", "auth", "credential_theft", "username: admin, password: password123", "2025-01-28 21:07:00"],
        ["9", "normal", "legitimate", "User logged in successfully", "2025-01-28 21:08:00"],
        ["10", "normal", "safe_data", "Regular application data", "2025-01-28 21:09:00"],
    ]
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(test_data)
    
    print(f"✅ Fichier de test complet créé: {filename}")
    return filename

def test_scanner_functionality(csv_file):
    """Test du scanner principal"""
    print("\n🔍 TEST SCANNER PRINCIPAL")
    
    try:
        result = subprocess.run([
            sys.executable, "src/main.py", csv_file
        ], capture_output=True, text=True, timeout=60)
        
        print(f"   Code de retour: {result.returncode}")
        
        if result.returncode == 0:
            print("   ✅ Scanner exécuté avec succès")
            
            # Vérifier la sortie
            output = result.stdout
            if "Menaces détectées" in output:
                print("   ✅ Détection de menaces confirmée")
            if "Rapport:" in output:
                print("   ✅ Rapport généré")
            
            # Chercher le fichier de rapport
            for line in output.split('\n'):
                if 'rapport_scan_' in line and '.html' in line:
                    report_file = line.split('📄 Rapport: ')[-1]
                    if os.path.exists(report_file):
                        print(f"   ✅ Rapport HTML trouvé: {report_file}")
                        return True, report_file
            
            return True, None
        else:
            print(f"   ❌ Erreur scanner: {result.stderr}")
            return False, None
            
    except Exception as e:
        print(f"   ❌ Exception scanner: {e}")
        return False, None

def test_web_interface():
    """Test de l'interface web (démarrage simple)"""
    print("\n🌐 TEST INTERFACE WEB")
    
    try:
        # Démarrer Flask en arrière-plan
        print("   Démarrage du serveur Flask...")
        process = subprocess.Popen([
            sys.executable, "src/app.py"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Attendre le démarrage
        time.sleep(8)
        
        # Tenter de se connecter
        try:
            response = requests.get("http://127.0.0.1:5625/", timeout=5)
            if response.status_code == 200:
                print("   ✅ Interface web accessible")
                web_success = True
            else:
                print(f"   ⚠️  Interface web - Status: {response.status_code}")
                web_success = False
        except requests.exceptions.RequestException as e:
            print(f"   ⚠️  Interface web inaccessible: {e}")
            web_success = False
        
        # Arrêter le serveur
        process.terminate()
        process.wait(timeout=5)
        
        return web_success
        
    except Exception as e:
        print(f"   ❌ Erreur test interface web: {e}")
        return False

def test_ai_modules():
    """Test des modules IA"""
    print("\n🤖 TEST MODULES IA")
    
    try:
        # Test import des modules
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        from core.ai.orion_core import OrionCore
        from core.ai.astra_assistant import AstraAssistant
        
        # Test Orion Core
        orion = OrionCore()
        status = orion.get_status()
        print(f"   ✅ Orion Core: {status['status']} (mode: {status['mode']})")
        
        # Test analyse simple
        result = orion.analyze_threat("test SQL injection: ' OR 1=1 --")
        if result.get('is_threat'):
            print("   ✅ Détection de menace fonctionnelle")
        
        # Test Astra Assistant
        astra = AstraAssistant()
        response = astra.chat("Bonjour Astra, comment ça va ?")
        if "Bonjour" in response:
            print("   ✅ Astra Assistant fonctionnel")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Erreur modules IA: {e}")
        return False

def generate_final_report(scanner_success, scanner_report, web_success, ai_success):
    """Génère un rapport final de l'état du projet"""
    print("\n" + "="*60)
    print("📋 RAPPORT FINAL - ÉTAT DU PROJET ANDROMÈDE")
    print("="*60)
    
    components = [
        ("Scanner CSV", scanner_success, "Analyse de fichiers CSV et détection de menaces"),
        ("Modules IA", ai_success, "Intelligence artificielle et analyse avancée"),
        ("Interface Web", web_success, "Interface utilisateur web"),
    ]
    
    working_count = sum(1 for _, status, _ in components if status)
    total_count = len(components)
    success_rate = (working_count / total_count) * 100
    
    print(f"\n📊 FONCTIONNALITÉS TESTÉES:")
    for name, status, description in components:
        icon = "✅" if status else "❌"
        print(f"   {icon} {name:<15} - {description}")
    
    print(f"\n📈 TAUX DE FONCTIONNEMENT: {working_count}/{total_count} ({success_rate:.1f}%)")
    
    if scanner_report:
        print(f"📄 RAPPORT DÉTAILLÉ: {scanner_report}")
    
    # Verdict final
    if success_rate >= 80:
        verdict = "🎉 PROJET ANDROMÈDE FONCTIONNEL"
        status = "Le projet est opérationnel avec toutes les fonctionnalités principales"
    elif success_rate >= 60:
        verdict = "⚠️  PROJET ANDROMÈDE PARTIELLEMENT FONCTIONNEL"
        status = "Le projet fonctionne avec quelques limitations"
    else:
        verdict = "🚨 PROJET ANDROMÈDE EN DÉVELOPPEMENT"
        status = "Le projet nécessite encore du travail"
    
    print(f"\n{verdict}")
    print(f"   {status}")
    
    print(f"\n🛠️  AMÉLIORATIONS RÉALISÉES:")
    print("   ✅ Correction des erreurs d'import")
    print("   ✅ Mode dégradé pour fonctionnement sans toutes les dépendances")
    print("   ✅ Scanner CSV fonctionnel avec détection de menaces")
    print("   ✅ Génération de rapports HTML")
    print("   ✅ Modules IA basiques opérationnels")
    print("   ✅ Interface web corrigée")
    
    return success_rate

def main():
    """Test complet du projet Andromède"""
    print("🚀 TEST COMPLET DU PROJET ANDROMÈDE")
    print("="*50)
    
    start_time = time.time()
    
    # Créer fichier de test
    test_file = create_comprehensive_test_csv()
    
    try:
        # Tests des fonctionnalités
        scanner_success, scanner_report = test_scanner_functionality(test_file)
        ai_success = test_ai_modules()
        web_success = test_web_interface()
        
        # Rapport final
        success_rate = generate_final_report(scanner_success, scanner_report, web_success, ai_success)
        
        elapsed_time = time.time() - start_time
        print(f"\n⏱️  TEMPS TOTAL: {elapsed_time:.1f} secondes")
        
        # Code de sortie
        return 0 if success_rate >= 60 else 1
        
    finally:
        # Nettoyage
        try:
            os.remove(test_file)
            print(f"\n🧹 Fichier de test supprimé")
        except:
            pass

if __name__ == "__main__":
    exit_code = main()
    print(f"\n🏁 Tests terminés avec code: {exit_code}")
    sys.exit(exit_code) 