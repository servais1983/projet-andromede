#!/usr/bin/env python3
"""
Test simple du scanner Andromède
"""

import os
import csv
import sys

# Créer un fichier CSV de test
def create_test_csv():
    filename = "test_menaces.csv"
    
    test_data = [
        ["source", "type", "data"],
        ["user_input", "form", "admin'; DROP TABLE users; --"],
        ["file_upload", "script", "<script>alert('XSS')</script>"],
        ["network", "scan", "nmap -sS 192.168.1.1"],
        ["email", "phishing", "Urgent: Verify your password at fake-bank.com"],
        ["file", "malware", "trojan.exe"],
    ]
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(test_data)
    
    print(f"✅ Fichier de test créé: {filename}")
    return filename

def main():
    print("🔍 Test simple du scanner Andromède")
    
    # Créer fichier de test
    test_file = create_test_csv()
    
    try:
        # Tester le scanner
        print(f"\n📊 Test du scanner avec {test_file}")
        result = os.system(f"python src/main.py {test_file}")
        
        if result == 0:
            print("✅ Scanner fonctionne correctement!")
        else:
            print("⚠️  Scanner a rencontré des problèmes")
        
        # Vérifier si un rapport a été généré
        if os.path.exists("security_report.html"):
            print("✅ Rapport HTML généré!")
            with open("security_report.html", 'r', encoding='utf-8') as f:
                content = f.read()
                print(f"📄 Taille du rapport: {len(content)} caractères")
        else:
            print("⚠️  Aucun rapport HTML trouvé")
        
    finally:
        # Nettoyage
        try:
            os.remove(test_file)
            print(f"🧹 Fichier de test supprimé")
        except:
            pass

if __name__ == "__main__":
    main() 