# 🚀 Guide Utilisateur - Projet Andromède

![Projet Andromède](andromeda.png)

## 🌟 Bienvenue dans Andromède

**Projet Andromède** est un scanner de menaces next-generation qui combine intelligence artificielle, analyse comportementale et visualisation 3D pour détecter et analyser les cybermenaces dans vos fichiers CSV.

---

## 📋 Table des Matières

1. [Installation Rapide](#installation-rapide)
2. [Démarrage](#démarrage)
3. [Interface Web](#interface-web)
4. [Utilisation du Scanner](#utilisation-du-scanner)
5. [Modules IA](#modules-ia)
6. [Rapports et Analyses](#rapports-et-analyses)
7. [Dépannage](#dépannage)
8. [Cas d'Usage](#cas-dusage)

---

## ⚡ Installation Rapide

### Prérequis
- **Python 3.8+** (recommandé : Python 3.12)
- **8 Go RAM minimum** (16 Go recommandé pour l'IA)
- **2 Go d'espace disque libre**

### Installation en 3 étapes

```bash
# 1. Cloner le projet
git clone https://github.com/servais1983/projet-andromede.git
cd projet-andromede

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Démarrer l'interface web
python src/app.py
```

🎯 **C'est tout !** Votre scanner Andromède est prêt à l'adresse : **http://127.0.0.1:5625**

---

## 🚀 Démarrage

### Option 1 : Interface Web (Recommandée)
```bash
python src/app.py
```
Puis ouvrez votre navigateur à l'adresse : **http://127.0.0.1:5625**

### Option 2 : Ligne de Commande
```bash
python src/main.py votre_fichier.csv
```

### Test Rapide
```bash
python test_simple.py
```
Ce test crée un fichier CSV avec des menaces réelles et vérifie que tout fonctionne.

---

## 🌐 Interface Web

### Page d'Accueil
L'interface moderne d'Andromède vous accueille avec :

- **Zone de glisser-déposer** pour vos fichiers CSV
- **Statut des modules IA** en temps réel
- **Visualisation des fonctionnalités** disponibles

### Fonctionnalités Principales

#### 📤 Upload de Fichiers
1. **Glissez-déposez** votre fichier CSV dans la zone prévue
2. Ou **cliquez** pour sélectionner votre fichier
3. Cliquez sur **"Analyser"**
4. Attendez les résultats (généralement < 5 secondes)

#### 📊 Résultats en Temps Réel
- **Score de risque** global
- **Nombre de menaces** détectées
- **Niveau de sévérité** par catégorie
- **Lien vers le rapport** détaillé HTML

#### 🤖 Assistant IA Astra
- Accès via `/chat`
- Posez des questions sur la cybersécurité
- Obtenez des conseils personnalisés
- Analysez des menaces spécifiques

---

## 🔍 Utilisation du Scanner

### Types de Menaces Détectées

| Type de Menace | Description | Exemples |
|----------------|-------------|----------|
| **Injection SQL** | Tentatives d'injection dans des bases de données | `'; DROP TABLE users; --` |
| **Cross-Site Scripting (XSS)** | Scripts malveillants | `<script>alert('XSS')</script>` |
| **Injection de Commandes** | Exécution de commandes système | `\|\| rm -rf /` |
| **Traversée de Répertoires** | Accès non autorisé aux fichiers | `../../../etc/passwd` |
| **Malwares** | Fichiers suspects et executables | `trojan.exe`, `virus.bat` |
| **Vol d'Identifiants** | Données sensibles exposées | `admin:password123` |
| **Scans Réseau** | Activités de reconnaissance | `nmap -sS 192.168.1.1` |

### Structure CSV Recommandée

```csv
id,source,type,data,timestamp
1,user_input,form,"admin'; DROP TABLE users; --",2025-01-28
2,file_upload,script,"<script>alert('XSS')</script>",2025-01-28
3,network,scan,"nmap -sS 192.168.1.1",2025-01-28
```

### Scoring des Menaces

- **🔴 Critique (90-100)** : Action immédiate requise
- **🟠 Élevé (70-89)** : Attention prioritaire
- **🟡 Moyen (50-69)** : Surveillance recommandée
- **🟢 Faible (30-49)** : Vigilance de routine
- **ℹ️ Info (0-29)** : Information générale

---

## 🤖 Modules IA

### Orion Core - Analyse Intelligente
**Fonctions :**
- Analyse comportementale des patterns
- Détection de menaces zero-day
- Classification automatique des risques
- Mode dégradé sans PyTorch

**Utilisation :**
```python
# Analyse directe via l'API
orion = OrionCore()
result = orion.analyze_threat("'; DROP TABLE users; --")
print(result['is_threat'])  # True
```

### Astra Assistant - IA Conversationnelle
**Capacités :**
- Questions/réponses sur la cybersécurité
- Conseils personnalisés
- Explication des menaces détectées
- Support en français

**Exemples de Questions :**
- *"Que faire si je détecte une injection SQL ?"*
- *"Comment interpréter ce rapport ?"*
- *"Quelles sont les bonnes pratiques de sécurité ?"*

### Modules Avancés (Quand Disponibles)
- **🔗 Andromeda Chain** : Blockchain de signatures de menaces
- **🛡️ Nebula Shield** : Protection en temps réel
- **⚛️ Quantum Shield** : Chiffrement post-quantique
- **🌌 StarMap Visualizer** : Visualisation 3D des menaces

---

## 📋 Rapports et Analyses

### Format du Rapport HTML

Chaque analyse génère un rapport HTML complet incluant :

#### 📊 Résumé Exécutif
- Score de risque global
- Nombre total de menaces
- Répartition par sévérité
- Temps d'analyse

#### 🔍 Détails des Menaces
- Localisation précise (ligne/colonne)
- Type de menace identifiée
- Contenu suspect
- Niveau de confiance

#### 💡 Recommandations
- Actions immédiates à prendre
- Mesures préventives
- Ressources complémentaires

#### 📈 Statistiques
- Analyse temporelle
- Patterns détectés
- Métriques de performance

### Exemple de Rapport
```
==========================================
RAPPORT D'ANALYSE ANDROMÈDE
==========================================
Fichier analysé : donnees_suspectes.csv
Date d'analyse : 28/01/2025 21:15:32
Score de risque : 140/200 (Élevé)

MENACES DÉTECTÉES : 3
- 1x Injection SQL (Critique)
- 1x XSS (Élevé) 
- 1x Scan réseau (Moyen)

RECOMMANDATIONS :
✓ Isoler les données concernées
✓ Vérifier les logs d'accès
✓ Renforcer la validation d'entrée
```

---

## 🛠️ Dépannage

### Problèmes Courants

#### ❌ "Modules IA non disponibles"
**Cause :** Dépendances manquantes
**Solution :**
```bash
pip install torch transformers
python src/app.py
```

#### ❌ "Port 5625 déjà utilisé"
**Solution :**
1. Changer le port dans `src/app.py`
2. Ou arrêter le processus existant

#### ❌ "Fichier CSV non reconnu"
**Vérifications :**
- Extension `.csv` correcte
- Encodage UTF-8
- Taille < 16 MB
- Format valide

#### ❌ Interface web inaccessible
**Solutions :**
1. Vérifier que le serveur est démarré
2. Tester : `http://127.0.0.1:5625`
3. Vérifier les pare-feux

### Mode Dégradé

Si les modules IA ne se chargent pas, Andromède fonctionne en **mode dégradé** :
- ✅ Scanner CSV fonctionnel
- ✅ Détection de patterns basiques
- ✅ Génération de rapports
- ❌ Analyse IA avancée désactivée

### Logs de Debug

Pour activer les logs détaillés :
```bash
export PYTHONPATH=.
python -v src/app.py
```

---

## 🎯 Cas d'Usage

### 1. Audit de Sécurité Interne
**Contexte :** Analyser les logs d'applications web
```bash
# Exporter les logs au format CSV
python src/main.py logs_application.csv
# Consulter le rapport généré
```

### 2. Forensic Digital
**Contexte :** Investigation post-incident
- Analyser les données extraites
- Identifier les vecteurs d'attaque
- Tracer la chronologie des événements

### 3. Validation de Code
**Contexte :** Vérifier la sécurité avant déploiement
- Scanner les inputs utilisateur
- Détecter les vulnérabilités
- Générer un rapport de conformité

### 4. Formation Sécurité
**Contexte :** Éduquer les équipes
- Créer des datasets pédagogiques
- Démontrer les types d'attaques
- Pratiquer la détection de menaces

### 5. Monitoring Continu
**Contexte :** Surveillance en temps réel
```bash
# Script de monitoring automatisé
while true; do
  python src/main.py logs_$(date +%Y%m%d).csv
  sleep 3600  # Analyse horaire
done
```

---

## 🚀 Fonctionnalités Avancées

### API REST

```bash
# Upload et analyse via API
curl -X POST -F "file=@data.csv" http://127.0.0.1:5625/upload

# Statut du système
curl http://127.0.0.1:5625/status

# Chat avec Astra
curl -X POST -H "Content-Type: application/json" \
  -d '{"message":"Explique-moi cette menace"}' \
  http://127.0.0.1:5625/ai-analysis
```

### Intégration avec d'Autres Outils

```python
# Intégration dans votre code Python
from src.main import CSVScanner

scanner = CSVScanner()
results = scanner.scan_file("data.csv")
print(f"Menaces détectées : {len(results['results'])}")
```

### Personnalisation des Règles

Modifiez `rules/csv_rules.json` pour ajouter vos propres patterns :
```json
{
  "name": "Ma règle personnalisée",
  "pattern": "mot_cle_suspect",
  "severity": "high",
  "score": 80,
  "description": "Détection de pattern personnalisé"
}
```

---

## 📞 Support et Contribution

### 🆘 Besoin d'Aide ?
- **Issues GitHub :** [Signaler un problème](https://github.com/servais1983/projet-andromede/issues)
- **Discussions :** Échanges communautaires
- **Documentation :** Consultez `/docs` pour plus de détails

### 🤝 Contribuer
1. Fork le projet
2. Créez votre branche feature
3. Commitez vos modifications
4. Poussez vers la branche
5. Créez une Pull Request

### 📧 Contact
- **Mainteneur :** Équipe Projet Andromède
- **License :** MIT
- **Version :** 1.0.0 (2025)

---

## 🎯 Prochaines Étapes

Maintenant que vous maîtrisez Andromède :

1. **📊 Analysez vos premiers fichiers** avec l'interface web
2. **🤖 Explorez l'assistant Astra** pour vos questions sécurité
3. **📋 Consultez les rapports détaillés** générés
4. **🔧 Personnalisez les règles** selon vos besoins
5. **🚀 Intégrez dans vos workflows** de sécurité

---

**🛡️ Andromède vous protège. La galaxie de la cybersécurité est entre vos mains !** 