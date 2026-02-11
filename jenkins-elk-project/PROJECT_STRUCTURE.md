# 📦 Structure du Projet Jenkins Security Dataset

## 📋 Vue d'ensemble

Projet complet pour collecter des logs applicatifs Jenkins avec **ELK Stack** et créer un dataset de détection d'attaques au format MITRE CAR.

## 🗂️ Arborescence des fichiers

```
jenkins-security-dataset/
│
├── 📄 README.md                          # Guide technique complet
├── 📄 QUICKSTART.md                      # Installation rapide (5 min)
├── 📄 PROJECT_STRUCTURE.md               # Ce fichier
│
├── 🐳 CONFIGURATION DOCKER
│   ├── docker-compose.yml                # Stack ELK + Jenkins + Filebeat
│   ├── jenkins-logging.properties        # Config logging FINEST
│   └── filebeat.yml                      # Config collecte STDOUT Docker
│
├── 🐍 SCRIPTS PYTHON
│   ├── scripts/
│   │   ├── generate_normal_traffic.py    # Génération trafic légitime
│   │   ├── transform_to_mitre_car.py     # Transformation → MITRE CAR
│   │   └── collect_dataset.py            # Orchestration complète
│   │
│   └── attack_scripts/
│       ├── brute_force.py                # Brute force (T1110.001)
│       ├── xxe_injection.py              # XXE (T1203)
│       └── rce_script_console.py         # RCE Script Console (T1059.007)
│
└── 📁 DOSSIERS DE DONNÉES
    └── dataset/
        ├── logs/                         # Logs bruts (Elasticsearch export)
        └── output/                       # Dataset MITRE CAR + stats
```

## 🎯 Description des fichiers

### 📄 Documentation

**README.md** - Guide technique complet
- Architecture ELK Stack
- Installation pas à pas
- Configuration Kibana
- Scénarios d'attaque détaillés
- Requêtes KQL
- Règles de détection
- Export MITRE CAR

**QUICKSTART.md** - Démarrage rapide
- Installation en 5 minutes
- Commandes essentielles
- Vérifications rapides
- Dépannage
- Dashboard Kibana

**PROJECT_STRUCTURE.md** - Ce fichier
- Organisation du projet
- Description de chaque fichier
- Workflow de collecte
- Points clés

### 🐳 Configuration Docker

**docker-compose.yml** - Infrastructure complète
```yaml
Services:
  - elasticsearch:  Stockage et indexation (port 9200)
  - kibana:        Visualisation (port 5601)
  - jenkins:       Application cible (port 8080)
  - filebeat:      Collecteur logs STDOUT Docker
```

**jenkins-logging.properties** - Configuration Java Logging ⚠️ CRITIQUE
```properties
handlers=java.util.logging.ConsoleHandler
.level=FINEST                              # Maximum détails
java.util.logging.ConsoleHandler.level=FINEST
hudson.level=FINEST
org.jenkinsci.level=FINEST
jenkins.level=FINEST
```
Sans ce fichier, les logs seront insuffisants !

**filebeat.yml** - Collecte STDOUT Docker
- Lit `/var/lib/docker/containers/*/*.log`
- Filtre conteneur Jenkins uniquement
- Parse JSON Docker
- Envoie vers Elasticsearch index `filebeat-*`

### 🐍 Scripts Python

#### Scripts de génération

**scripts/generate_normal_traffic.py** - Trafic légitime
```python
# Simule des utilisateurs normaux
# Actions: page accueil, jobs, builds, logs
# Multi-threading pour plusieurs users simultanés
# Comportement réaliste avec pauses aléatoires
```

Usage:
```bash
python3 scripts/generate_normal_traffic.py \
  --target http://localhost:8080 \
  --users 10 \
  --duration 3600
```

#### Scripts d'attaque

**attack_scripts/brute_force.py** - T1110.001
```python
# Attaque par dictionnaire
# 20+ mots de passe communs
# Mode agressif avec variantes
# Statistiques d'attaque
```

**attack_scripts/xxe_injection.py** - T1203
```python
# Lecture fichiers sensibles (/etc/passwd, secrets)
# SSRF vers metadata AWS
# Billion Laughs (DoS)
# Payloads XML malveillants
```

**attack_scripts/rce_script_console.py** - T1059.007
```python
# Reconnaissance système
# Accès filesystem
# Exécution commandes OS
# Tentative reverse shell
# Élévation de privilèges
# Persistence
```

Usage général:
```bash
python3 attack_scripts/<script>.py \
  --target http://localhost:8080 \
  --duration 300
```

#### Scripts de transformation

**scripts/transform_to_mitre_car.py** - Export MITRE CAR
```python
# Parse logs Jenkins
# Détecte patterns d'attaque
# Extrait métadonnées réseau
# Génère format MITRE CAR
# Annotation automatique
```

Format de sortie:
```json
{
  "metadata": {
    "total_events": 15000,
    "malicious_events": 1250
  },
  "events": [
    {
      "event_id": "...",
      "timestamp": "2024-02-11T10:15:23Z",
      "metadata": {
        "is_malicious": true,
        "attack_type": "brute_force",
        "mitre_technique": "T1110.001"
      }
    }
  ]
}
```

**scripts/collect_dataset.py** - Orchestration complète
```python
# Automatise tout le workflow:
# 1. Vérifie Jenkins est prêt
# 2. Lance trafic normal
# 3. Exécute toutes les attaques
# 4. Export depuis Elasticsearch
# 5. Transformation MITRE CAR
# 6. Génération statistiques
```

Usage:
```bash
python3 scripts/collect_dataset.py \
  --jenkins-url http://localhost:8080 \
  --normal-duration 3600 \
  --normal-users 10
```

## 🚀 Workflows

### Workflow Rapide (5 minutes de setup)

```bash
# 1. Démarrer
docker-compose up -d

# 2. Attendre Jenkins
# Accéder http://localhost:8080
# Mot de passe: docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword

# 3. Kibana
# Accéder http://localhost:5601
# Créer index pattern: filebeat-*

# 4. Vérifier logs
# Kibana Discover → filter: container.name: "jenkins"

# 5. Collecter dataset
python3 scripts/collect_dataset.py
```

### Workflow Complet (2-3 heures)

```
1. docker-compose up -d
2. Configurer Jenkins (http://localhost:8080)
3. Créer index pattern Kibana (http://localhost:5601)
4. Vérifier logs FINEST dans Kibana
5. Générer trafic normal (1h)
   → python3 scripts/generate_normal_traffic.py
6. Pause 5 minutes
7. Attaque brute force (5 min)
   → python3 attack_scripts/brute_force.py
8. Pause 1 minute
9. Attaque XXE (5 min)
   → python3 attack_scripts/xxe_injection.py
10. Pause 1 minute
11. Attaque RCE (5 min)
    → python3 attack_scripts/rce_script_console.py
12. Attendre propagation logs (2 min)
13. Export Elasticsearch
    → curl localhost:9200/filebeat-*/_search
14. Transformation MITRE CAR
    → python3 scripts/transform_to_mitre_car.py
15. Statistiques
    → Automatique dans le dataset
```

## 📊 Visualisation Kibana

### Requêtes KQL essentielles

```kql
# Tous logs Jenkins
container.name: "jenkins"

# Brute force
container.name: "jenkins" AND message: "authentication failed"

# XXE
container.name: "jenkins" AND message: "<!ENTITY"

# RCE
container.name: "jenkins" AND message: "script console"

# Erreurs critiques
container.name: "jenkins" AND log.level: "SEVERE"
```

### Dashboards recommandés

**Dashboard 1: Security Overview**
- Panel: Timeline authentifications (Line chart)
- Panel: Distribution niveaux log (Pie)
- Panel: Top erreurs (Data table)
- Panel: Activité Script Console (Metric)

**Dashboard 2: Attack Detection**
- Panel: Brute force timeline
- Panel: XXE attempts
- Panel: RCE indicators
- Panel: Anomalies temporelles

## 🛡️ Règles de Détection Kibana

### Règles implémentées

1. **Brute Force** - >10 auth failed en 5 min
2. **Script Console Access** - Usage détecté
3. **XXE Injection** - Entités externes détectées
4. **Multiple Errors** - >5 SEVERE en 10 min

Configuration : Menu → Security → Rules → Detection rules

## 📁 Dataset Final

### Structure
```
dataset/
├── logs/
│   └── jenkins-logs-raw.json          # Export Elasticsearch
└── output/
    ├── jenkins-logs-mitre-car.json    # Format MITRE CAR
    └── dataset-statistics.json        # Stats du dataset
```

### Statistiques incluses
- Total événements
- Événements malveillants vs bénins
- Distribution types d'attaque
- Techniques MITRE ATT&CK
- Timeline temporelle

## 🎯 Points clés du projet

### ✅ Forces

1. **Collecte STDOUT** - Filebeat lit directement Docker containers
2. **Niveau FINEST** - Maximum de détails dans les logs
3. **Séparation claire** - Timestamps distincts normal/attaques
4. **Format standardisé** - MITRE CAR interopérable
5. **Annotations auto** - Détection patterns d'attaque
6. **Reproductible** - Scripts entièrement automatisés
7. **ELK natif** - Visualisation Kibana puissante

### ⚠️ Points d'attention

1. **Ressources** - Minimum 4GB RAM pour la stack
2. **Temps** - Collecte complète ~2h minimum
3. **Credentials** - Utiliser admin/admin pour tests
4. **Délais** - Respecter pauses entre attaques
5. **Vérification** - Toujours vérifier logs FINEST

## 🛠️ Prérequis Techniques

**Système:**
- Ubuntu 20.04+ (ou similaire)
- Docker 20.10+
- Docker Compose 1.29+
- Python 3.8+

**Ressources:**
- 4GB RAM minimum
- 2 CPU cores
- 10GB disque libre

**Bibliothèques:**
```bash
pip3 install requests
```

## 📝 Checklist Qualité Dataset

- [ ] Elasticsearch accessible (localhost:9200)
- [ ] Kibana accessible (localhost:5601)
- [ ] Jenkins configuré avec admin/admin
- [ ] Index pattern `filebeat-*` créé
- [ ] Logs FINEST visibles dans Discover
- [ ] Trafic normal collecté (min 1h)
- [ ] 3 types d'attaques exécutées
- [ ] Logs exportés depuis Elasticsearch
- [ ] Transformation MITRE CAR réussie
- [ ] Statistiques générées
- [ ] Règles de détection testées
- [ ] Dashboards Kibana créés

## 🎓 Objectifs Pédagogiques Couverts

- [x] Déploiement applications réelles (Jenkins, ELK)
- [x] Instrumentation et collecte logs (Filebeat)
- [x] Conception scénarios d'attaque (3 types MITRE)
- [x] Tests de charge multi-utilisateurs
- [x] Utilisation Elastic Stack complet
- [x] Transformation format MITRE CAR
- [x] Production dataset scientifique
- [x] Documentation technique complète

## 📚 Ressources Supplémentaires

- [MITRE ATT&CK](https://attack.mitre.org/) - Framework attaques
- [MITRE CAR](https://car.mitre.org/) - Format analytics
- [Jenkins Security](https://www.jenkins.io/security/) - CVEs Jenkins
- [Filebeat Docs](https://www.elastic.co/guide/en/beats/filebeat/) - Collecteur
- [Kibana Query Language](https://www.elastic.co/guide/en/kibana/current/kuery-query.html) - KQL

## 🏆 Livrables Finaux

1. ✅ **Dataset MITRE CAR** (JSON, ~15k événements)
2. ✅ **Statistiques** (Répartition attaques)
3. ✅ **Dashboards Kibana** (Exportables JSON)
4. ✅ **Règles de détection** (4+ règles testées)
5. ✅ **Documentation** (README complet)
6. ✅ **Scripts** (Reproductibles)
7. ✅ **Rapport** (Analyse des résultats)

---

**Votre projet de cybersécurité est prêt ! 🚀**

Pour démarrer : consulter **QUICKSTART.md**  
Pour les détails : consulter **README.md**
