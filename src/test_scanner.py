import csv
import tempfile
import os

# Création d'un fichier CSV de test avec des contenus suspects
def create_test_csv():
    temp_dir = tempfile.gettempdir()
    test_file = os.path.join(temp_dir, 'test_malicious.csv')
    
    with open(test_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Nom', 'Description', 'Chemin'])
        writer.writerow(['1', 'Document1', 'Fichier normal', 'C:/Documents/rapport.docx'])
        writer.writerow(['2', 'Script suspect', 'Script PowerShell suspect', 'C:/Scripts/invoke-expression.ps1'])
        writer.writerow(['3', 'Ransomware détecté', 'Possible ransomware', 'C:/temp/lockbit.exe'])
        writer.writerow(['4', 'Lien suspect', 'URL de téléchargement', 'https://malicious-site.com/download.php'])
        writer.writerow(['5', 'Fichier système', 'Fichier système Windows', 'C:/Windows/System32/cmd.exe'])
    
    print(f"Fichier de test créé: {test_file}")
    return test_file

# Test du scanner
def test_scanner():
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.main import CSVScanner
    
    # Création du fichier de test
    test_file = create_test_csv()
    
    # Initialisation du scanner
    scanner = CSVScanner()
    
    # Analyse du fichier
    print("Analyse du fichier de test...")
    report = scanner.scan_file(test_file)
    
    # Affichage des résultats
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
    
    return html_report

if __name__ == "__main__":
    test_scanner()
