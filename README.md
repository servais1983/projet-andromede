# 🌌 Projet Andromède

**Système de cybersécurité défensif production-ready** — détection de menaces CSV, cryptographie post-quantique, blockchain d'audit, isolation de processus et surveillance réseau temps réel.

[![CI](https://github.com/servais1983/projet-andromede/actions/workflows/ci.yml/badge.svg)](https://github.com/servais1983/projet-andromede/actions)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org)
[![Tests](https://img.shields.io/badge/tests-46%20passed-brightgreen)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Fonctionnalités réelles

### 🤖 Orion Core — Classificateur ML (scikit-learn)
Vrai pipeline machine learning entraîné sur ~60 exemples labellisés :
- **TF-IDF** (char n-grams 2–5, 8 000 features) + **Régression Logistique** (balanced)
- Sortie : probabilité de menace par classe + sévérité
- Persistance du modèle via `joblib` (`config/orion_model.joblib`)
- Fonctionne sans GPU — pur CPU scikit-learn

### ⛓️ Andromeda Chain — Blockchain réelle
Blockchain SHA-256 entièrement implémentée :
- **Preuve de travail** (Proof of Work, difficulté configurable)
- **Arbre de Merkle** pour l'intégrité des signatures
- Validation complète de la chaîne (hash précédent + PoW + Merkle)
- Persistance JSON (`config/andromeda_chain.json`)
- Thread de minage automatique toutes les 60 secondes

### 🔐 Quantum Shield — Cryptographie post-quantique hybride
Implémentation réelle via la bibliothèque `cryptography` (conforme NIST) :
- **AES-256-GCM** — chiffrement symétrique (128 bits de sécurité quantique contre Grover)
- **HKDF-SHA-256** — dérivation de clé (NIST SP 800-56C)
- **X25519** — échange de clé Diffie-Hellman
- **Ed25519** — signatures numériques
- **SHA-3 / BLAKE2b** — hachage résistant aux attaques quantiques
- Nonces 96 bits aléatoires, tags d'authentification GCM inclus

### 🧪 Neural Sandbox — Isolation réelle des processus
Isolation système complète via le noyau Linux :
- `resource.setrlimit` : limites CPU (RLIMIT_CPU), mémoire (RLIMIT_AS), fichiers (RLIMIT_FSIZE), processus (RLIMIT_NPROC)
- `os.setsid()` : nouveau groupe de processus (isolation des signaux)
- `os.killpg()` : kill récursif du groupe entier (évite les zombies)
- **psutil** : surveillance mémoire en temps réel avec kill automatique
- Environnement minimal : `PATH=/usr/bin:/bin` uniquement

### 🛡️ Nebula Shield — Surveillance réseau/processus temps réel
Surveillance système réelle via **psutil** :
- Inventaire des processus actifs (CPU, RAM, connexions)
- Détection de processus suspects (noms, seuils CPU/mémoire)
- Inventaire des connexions réseau TCP/UDP avec détection de ports suspects
- **SecurityBubble** : liste blanche/noire de PIDs
- Alertes JSON horodatées avec niveaux de sévérité

---

## Architecture

```
projet-andromede/
├── src/
│   ├── app.py          # Flask factory + toutes les routes API
│   └── main.py         # Scanner CSV
├── core/
│   ├── ai/
│   │   └── orion_core.py          # ML pipeline scikit-learn
│   ├── blockchain/
│   │   └── andromeda_chain.py     # Blockchain SHA-256 + PoW + Merkle
│   ├── quantum/
│   │   └── quantum_shield.py      # AES-256-GCM + HKDF + X25519 + Ed25519
│   ├── sandbox/
│   │   └── neural_sandbox.py      # Isolation processus (resource + psutil)
│   └── nebula/
│       └── nebula_shield.py       # Surveillance réseau/processus (psutil)
├── tests/
│   ├── test_scanner.py            # Tests scanner CSV
│   ├── test_app.py                # Tests routes web
│   └── test_security_modules.py  # Tests modules sécurité (31 tests)
├── Dockerfile                     # Multi-stage, non-root uid 1001
├── docker-compose.yml             # app + postgres + redis
├── gunicorn.conf.py               # Production WSGI
└── .github/workflows/ci.yml      # lint → test → security → docker
```

---

## API REST

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/healthz` | Health check (uptime, version) |
| GET | `/status` | Statut des modules |
| POST | `/upload` | Scanner un fichier CSV |
| GET | `/api/status/all` | Vue consolidée de tous les modules |
| GET | `/api/quantum/status` | Statut Quantum Shield |
| POST | `/api/quantum/encrypt` | Chiffrement AES-256-GCM |
| POST | `/api/quantum/sign` | Signature Ed25519 |
| GET | `/api/blockchain/status` | Statut blockchain |
| GET | `/api/blockchain/chain` | Liste des blocs |
| POST | `/api/blockchain/add` | Ajouter une menace et miner |
| GET | `/api/nebula/status` | Statut Nebula Shield |
| GET | `/api/nebula/snapshot` | Snapshot système + alertes |
| GET | `/api/sandbox/status` | Statut Neural Sandbox |

### Exemples

```bash
# Chiffrer avec AES-256-GCM
curl -X POST http://localhost:5625/api/quantum/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "données sensibles"}'

# Ajouter une menace à la blockchain
curl -X POST http://localhost:5625/api/blockchain/add \
  -H "Content-Type: application/json" \
  -d '{"threat_data": {"type": "sql_injection", "severity": "critical"}}'

# Snapshot système en temps réel
curl http://localhost:5625/api/nebula/snapshot
```

---

## Démarrage rapide

### Docker (recommandé)
```bash
cp .env.example .env          # Configurer SECRET_KEY, DB_PASSWORD...
docker compose up -d
```

### Développement local
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export FLASK_ENV=development
gunicorn 'src.app:app' --config gunicorn.conf.py
```

### Tests
```bash
pip install -r requirements-dev.txt
pytest tests/ -v                        # 46 tests
pytest tests/test_security_modules.py  # modules sécurité uniquement
```

---

## Variables d'environnement

| Variable | Requis | Description |
|----------|--------|-------------|
| `SECRET_KEY` | **Oui (prod)** | Clé secrète Flask — minimum 32 octets hex |
| `FLASK_ENV` | Non | `production` (défaut) ou `development` |
| `DATABASE_URL` | Non | PostgreSQL URL |
| `REDIS_URL` | Non | Redis URL (cache, sessions) |
| `UPLOAD_FOLDER` | Non | Dossier temporaire pour les uploads |
| `MAX_UPLOAD_MB` | Non | Taille max upload (défaut : 16 MB) |

---

## Sécurité production

- **SECRET_KEY** : refus de démarrage en production si absent
- **Gunicorn** : workers = `cpu_count × 2 + 1`, timeout 30s
- **Docker** : image multi-stage, utilisateur non-root (uid 1001)
- **Rate limiting** : 30 req/min sur les endpoints sensibles
- **Upload** : validation type MIME + taille + chemin sécurisé
- **CI/CD** : bandit (SAST), flake8, black, isort à chaque push

---

## Honnêteté technique

| Ce qui est **réel** | Ce qui est **désactivé faute de dépendances** |
|---------------------|----------------------------------------------|
| AES-256-GCM + HKDF + Ed25519 | Kyber-768 (nécessite liboqs compilé) |
| Blockchain SHA-256 + PoW + Merkle | — |
| ML scikit-learn TF-IDF + LogReg | BERT/Transformers (nécessite PyTorch) |
| Isolation resource.setrlimit + psutil | Isolation Docker-in-Docker (nécessite Docker) |
| Surveillance psutil TCP/process | eBPF/seccomp (nécessite privilèges root) |

---

## Licence

MIT — voir [LICENSE](LICENSE)
