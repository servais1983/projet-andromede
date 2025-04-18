# Guide de D\u00e9veloppement

## \ud83e\udde9 Structure du Projet

```
andromede/
\u251c\u2500\u2500 core/
\u2502   \u251c\u2500\u2500 blockchain/          # Module Andromeda Chain
\u2502   \u2502   \u251c\u2500\u2500 nodes/
\u2502   \u2502   \u251c\u2500\u2500 smart_contracts/
\u2502   \u2502   \u2514\u2500\u2500 consensus.py
\u2502   \u251c\u2500\u2500 ai/                  # Module Orion Core
\u2502   \u2502   \u251c\u2500\u2500 threat_detection/
\u2502   \u2502   \u251c\u2500\u2500 generative/
\u2502   \u2502   \u2514\u2500\u2500 models/
\u2502   \u2514\u2500\u2500 shield/              # Module Nebula Shield
\u2502       \u251c\u2500\u2500 sandboxing/
\u2502       \u2514\u2500\u2500 microsegmentation/
\u251c\u2500\u2500 api/
\u2502   \u251c\u2500\u2500 threat_intel.py      # API Darkweb Monitoring
\u2502   \u2514\u2500\u2500 decentralised.py     # API P2P
\u251c\u2500\u2500 config/
\u2502   \u2514\u2500\u2500 quantum_encryption.yaml
\u2514\u2500\u2500 tests/
```

## \ud83d\ude80 Mise en Route

### Pr\u00e9requis

- Python 3.9+
- Docker & Docker Compose
- GPU compatible CUDA (recommand\u00e9 pour les composants IA)
- Node.js 16+ (pour l'interface utilisateur)

### D\u00e9pendances Principales

```
# \u00c0 installer via pip
sawtooth-sdk>=1.2
torch>=2.0
docker>=6.0
python-iptables
tensorflow>=2.10
hyperledger-fabric-sdk
ipfs-api
```

### Configuration Initiale

1. Cloner le d\u00e9p\u00f4t
```bash
git clone https://github.com/servais1983/projet-andromede.git
cd projet-andromede
```

2. Cr\u00e9er un environnement virtuel
```bash
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\\Scripts\\activate
```

3. Installer les d\u00e9pendances
```bash
pip install -r requirements.txt
```

4. Configurer les param\u00e8tres de base
```bash
cp config/quantum_encryption.example.yaml config/quantum_encryption.yaml
# \u00c9diter le fichier selon vos besoins
```

## \ud83d\udcbb Flux de D\u00e9veloppement

### D\u00e9marrer le N\u0153ud Blockchain de Test

```bash
python -m core.blockchain.nodes.bootstrap_node --port 9050
```

### Ex\u00e9cuter le Sandbox IA

```bash
docker-compose up -f docker/sandbox.yml
```

### Lancer les Tests

```bash
python -m pytest tests/
```

## \ud83d\udcdd Conventions de Code

- **Style Python**: Suivre PEP 8
- **Documentation**: Docstrings au format Google pour toutes les fonctions/classes
- **Tests**: Pytest pour tous les modules critiques
- **Commits Git**: Format Conventional Commits (feat:, fix:, docs:, etc.)

## \ud83d\udd04 Workflow de Contribution

1. Cr\u00e9er une branche \u00e0 partir de `develop`
2. Impl\u00e9menter les changements avec tests
3. Soumettre une Pull Request vers `develop`
4. Attendre la revue de code et l'approbation
5. Les d\u00e9ploiements en production sont faits \u00e0 partir de `main`