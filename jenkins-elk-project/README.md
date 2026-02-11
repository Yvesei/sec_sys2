# Guide Complet - Collecte de Logs Jenkins avec ELK Stack

## 📋 Table des Matières
1. [Architecture](#architecture)
2. [Installation](#installation)
3. [Configuration Kibana](#configuration-kibana)
4. [Scénarios d'Attaque](#scénarios-dattaque)
5. [Visualisation](#visualisation)
6. [Export MITRE CAR](#export-mitre-car)
7. [Règles de Détection](#règles-de-détection)

## 🏗️ Architecture

### Stack ELK pour Logs Jenkins

```
Jenkins (Docker STDOUT) 
    ↓
Filebeat (Collecteur)
    ↓
Elasticsearch (Stockage & Indexation)
    ↓
Kibana (Visualisation & Analyse)
```

### Composants

- **Jenkins** : Application cible avec logging FINEST
- **Filebeat** : Collecte les logs depuis `/var/lib/docker/containers/`
- **Elasticsearch** : Stockage et indexation des logs
- **Kibana** : Interface de visualisation et création de règles

## 🚀 Installation

### Prérequis
```bash
# Docker et Docker Compose
sudo apt update
sudo apt install docker.io docker-compose -y

# Python 3.8+ et requests
sudo apt install python3 python3-pip -y
pip3 install requests

# Ajouter l'utilisateur au groupe docker
sudo usermod -aG docker $USER
newgrp docker
```

### Déploiement

```bash
# 1. Créer le projet
mkdir jenkins-security-dataset
cd jenkins-security-dataset

# 2. Placer les fichiers de configuration
# - docker-compose.yml
# - jenkins-logging.properties
# - filebeat.yml
# - scripts/ et attack_scripts/

# 3. Démarrer la stack
docker-compose up -d

# 4. Vérifier les services
docker-compose ps

# 5. Attendre que tout soit prêt (2-3 minutes)
curl http://localhost:9200/_cluster/health
curl http://localhost:5601/api/status
curl http://localhost:8080
```

## ⚙️ Configuration

### 1. Jenkins

#### Premier accès
```bash
# Récupérer le mot de passe initial
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

- Accéder à http://localhost:8080
- Coller le mot de passe
- Installer les plugins recommandés
- Créer un utilisateur admin (admin/admin)

#### Vérifier les logs FINEST
```bash
# Les logs doivent être très détaillés
docker logs jenkins 2>&1 | grep FINEST | head -20
```

### 2. Kibana

#### Accès
- URL : http://localhost:5601
- Pas d'authentification (mode dev)

#### Créer l'Index Pattern

1. **Menu (☰) → Stack Management → Index Patterns**
2. **Create index pattern**
3. Index pattern : `filebeat-*`
4. Time field : `@timestamp`
5. **Create**

#### Première visualisation

1. **Menu → Discover**
2. Sélectionner `filebeat-*`
3. Filtrer Jenkins : `container.name: "jenkins"`
4. Vérifier les logs FINEST : `container.name: "jenkins" AND log.level: "FINEST"`

## 🎯 Scénarios d'Attaque

### Trafic Normal

Le script `generate_normal_traffic.py` simule des utilisateurs légitimes :
- Consultation de la page d'accueil
- Liste des jobs
- Déclenchement de builds
- Consultation des logs
- Configuration de jobs

```bash
python3 scripts/generate_normal_traffic.py \
  --target http://localhost:8080 \
  --users 10 \
  --duration 3600
```

### Attaques Implémentées

#### 1. Brute Force (T1110.001)
```bash
python3 attack_scripts/brute_force.py \
  --target http://localhost:8080 \
  --duration 300 \
  --delay 0.5
```

**Indicateurs dans Kibana :**
```kql
message: "authentication failed" OR message: "login failed"
```

#### 2. XXE Injection (T1203)
```bash
python3 attack_scripts/xxe_injection.py \
  --target http://localhost:8080 \
  --user admin \
  --password admin \
  --duration 300
```

**Indicateurs dans Kibana :**
```kql
message: "<!ENTITY" OR message: "<!DOCTYPE" OR message: "SYSTEM"
```

#### 3. RCE Script Console (T1059.007)
```bash
python3 attack_scripts/rce_script_console.py \
  --target http://localhost:8080 \
  --user admin \
  --password admin \
  --attack-type all
```

**Indicateurs dans Kibana :**
```kql
message: "script console" OR message: "groovy" OR message: "execute()"
```

## 📊 Visualisation dans Kibana

### Requêtes KQL Essentielles

#### Logs Jenkins uniquement
```kql
container.name: "jenkins"
```

#### Attaques par type

**Brute Force :**
```kql
container.name: "jenkins" AND message: "authentication failed"
```

**XXE Injection :**
```kql
container.name: "jenkins" AND (message: "<!ENTITY" OR message: "SYSTEM \"file:")
```

**RCE :**
```kql
container.name: "jenkins" AND (message: "script console" OR message: "groovy")
```

#### Par niveau de sévérité
```kql
container.name: "jenkins" AND (log.level: "WARNING" OR log.level: "SEVERE")
```

### Créer des Dashboards

#### Dashboard : Vue d'ensemble sécurité

1. **Menu → Dashboard → Create dashboard**

2. **Panel 1 : Timeline des authentifications**
   - Visualization : Line
   - Metrics : Count
   - Buckets : 
     - X-axis : Date Histogram `@timestamp`
     - Split series : 
       - Filter 1: `message: "authentication failed"` (label: Failed)
       - Filter 2: `message: "authenticated"` (label: Success)

3. **Panel 2 : Distribution des niveaux de log**
   - Visualization : Pie
   - Metrics : Count
   - Buckets : Split slices par `log.level`

4. **Panel 3 : Top 10 des messages d'erreur**
   - Visualization : Data table
   - Metrics : Count
   - Buckets : 
     - Split rows : Terms sur `message.keyword`
     - Size : 10
   - Filter : `log.level: "SEVERE"`

5. **Panel 4 : Activité Script Console**
   - Visualization : Metric
   - Metrics : Count
   - Add filter : `message: "script console"`

6. **Sauvegarder** : "Jenkins Security Dashboard"

## 🔄 Export et Transformation MITRE CAR

### Export depuis Elasticsearch

```bash
# Export JSON complet
curl -X GET "localhost:9200/filebeat-*/_search?size=10000&pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "must": [
          { "match": { "container.name": "jenkins" } }
        ]
      }
    },
    "sort": [{ "@timestamp": "asc" }]
  }' > dataset/logs/jenkins-logs-raw.json
```

### Transformation MITRE CAR

```bash
python3 scripts/transform_to_mitre_car.py \
  --input dataset/logs/jenkins-logs-raw.json \
  --output dataset/output/jenkins-logs-mitre-car.json \
  --annotate
```

### Format MITRE CAR

```json
{
  "metadata": {
    "version": "1.0",
    "total_events": 15000,
    "malicious_events": 1250,
    "benign_events": 13750
  },
  "events": [
    {
      "event_id": "abc123...",
      "timestamp": "2024-02-11T10:15:23Z",
      "source": {
        "type": "application",
        "name": "jenkins",
        "component": "hudson.security"
      },
      "action": {
        "type": "authentication-attempt",
        "result": "failure"
      },
      "actor": {
        "user": "attacker",
        "ip": "192.168.1.100"
      },
      "metadata": {
        "is_malicious": true,
        "attack_type": "brute_force",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "confidence": "high"
      }
    }
  ]
}
```

## 🛡️ Règles de Détection dans Kibana

### Accès aux règles
**Menu → Security → Rules → Detection rules (SIEM)**

### Règle 1 : Brute Force Detection

```yaml
Name: Jenkins Brute Force Attack
Description: Détecte plus de 10 tentatives d'authentification échouées en 5 minutes

Rule type: Custom query
Index patterns: filebeat-*

Query:
container.name: "jenkins" AND message: "authentication failed"

Conditions:
- Threshold: 10
- Time window: 5 minutes
- Group by: source.ip (si disponible)

Severity: High
Risk score: 75

Actions:
- Index alert
- Send email/webhook
```

### Règle 2 : Script Console Usage

```yaml
Name: Jenkins Script Console Access
Description: Détecte l'utilisation du Script Console (potentiel RCE)

Rule type: Custom query
Index patterns: filebeat-*

Query:
container.name: "jenkins" AND (message: "script console" OR message: "groovy")

Conditions:
- At least 1 match

Severity: Critical
Risk score: 90

Actions:
- Index alert
- Send email immediately
```

### Règle 3 : XXE Injection Attempt

```yaml
Name: Jenkins XXE Injection Attempt
Description: Détecte des tentatives d'injection XXE

Rule type: Custom query
Index patterns: filebeat-*

Query:
container.name: "jenkins" AND (message: "<!ENTITY" OR message: "<!DOCTYPE" OR message: "SYSTEM \"file:")

Conditions:
- At least 1 match

Severity: High
Risk score: 85
```

### Règle 4 : Multiple Severe Errors

```yaml
Name: Jenkins Multiple Critical Errors
Description: Détecte plusieurs erreurs critiques en peu de temps

Rule type: Custom query
Index patterns: filebeat-*

Query:
container.name: "jenkins" AND log.level: "SEVERE"

Conditions:
- Threshold: 5
- Time window: 10 minutes

Severity: Medium
Risk score: 50
```

## 📝 Workflow de Collecte Complet

### Option A : Automatique (Recommandée)

```bash
python3 scripts/collect_dataset.py \
  --jenkins-url http://localhost:8080 \
  --normal-duration 3600 \
  --normal-users 10 \
  --backend elasticsearch
```

Ce script :
1. Vérifie que Jenkins est prêt
2. Génère 1h de trafic normal (10 users)
3. Exécute toutes les attaques séquentiellement
4. Export les logs depuis Elasticsearch
5. Transforme au format MITRE CAR
6. Génère les statistiques

### Option B : Manuelle (Contrôle total)

```bash
# Phase 1 : Trafic normal (1 heure)
python3 scripts/generate_normal_traffic.py \
  --target http://localhost:8080 \
  --users 10 \
  --duration 3600

# Phase 2 : Attaques
sleep 300  # Pause entre phases

# Attaque 1 : Brute Force
python3 attack_scripts/brute_force.py \
  --target http://localhost:8080 \
  --duration 300
sleep 60

# Attaque 2 : XXE
python3 attack_scripts/xxe_injection.py \
  --target http://localhost:8080 \
  --user admin --password admin \
  --duration 300
sleep 60

# Attaque 3 : RCE
python3 attack_scripts/rce_script_console.py \
  --target http://localhost:8080 \
  --user admin --password admin \
  --attack-type all

# Phase 3 : Export
sleep 120  # Attendre propagation logs

curl -X GET "localhost:9200/filebeat-*/_search?size=10000&pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": { "match": { "container.name": "jenkins" } },
    "sort": [{ "@timestamp": "asc" }]
  }' > dataset/logs/jenkins-logs-raw.json

# Phase 4 : Transformation
python3 scripts/transform_to_mitre_car.py \
  --input dataset/logs/jenkins-logs-raw.json \
  --output dataset/output/jenkins-logs-mitre-car.json \
  --annotate
```

## 🔍 Validation du Dataset

### Checklist Qualité

- [ ] **Logs STDOUT collectés** : `docker logs jenkins | grep FINEST`
- [ ] **Logs dans Elasticsearch** : `curl localhost:9200/filebeat-*/_count`
- [ ] **Logs visibles dans Kibana** : Discover avec filter Jenkins
- [ ] **Séparation trafic normal/attaques** : Timestamps distincts
- [ ] **Annotations présentes** : Champs `is_malicious` dans MITRE CAR
- [ ] **Format MITRE CAR valide** : JSON parsable avec structure correcte
- [ ] **Règles de détection testées** : Alertes déclenchées dans Kibana
- [ ] **Documentation complète** : README, statistiques, métadonnées

## 🐛 Dépannage

### Filebeat ne collecte pas les logs

```bash
# Vérifier Filebeat
docker logs filebeat

# Redémarrer
docker-compose restart filebeat

# Vérifier la config
docker exec filebeat cat /usr/share/filebeat/filebeat.yml
```

### Logs FINEST absents

```bash
# Vérifier la config Jenkins
docker exec jenkins cat /var/jenkins_home/logging.properties

# Redémarrer Jenkins
docker-compose restart jenkins
sleep 120

# Vérifier à nouveau
docker logs jenkins 2>&1 | grep FINEST
```

### Elasticsearch plein

```bash
# Supprimer les anciens indices
curl -X DELETE "localhost:9200/filebeat-2024.01.*"

# Ou augmenter le stockage dans docker-compose.yml
```

### Kibana lent

```bash
# Augmenter la mémoire ES dans docker-compose.yml
# ES_JAVA_OPTS: -Xms4g -Xmx4g

docker-compose down
docker-compose up -d
```

## 📚 Ressources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE CAR](https://car.mitre.org/)
- [Jenkins Security](https://www.jenkins.io/security/)
- [Filebeat Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Kibana Query Language](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)

## 🎯 Livrables Finaux

À l'issue du projet :

1. ✅ Dataset MITRE CAR (`jenkins-logs-mitre-car.json`)
2. ✅ Statistiques (`dataset-statistics.json`)
3. ✅ Dashboards Kibana exportés (JSON)
4. ✅ Règles de détection documentées
5. ✅ Documentation technique complète
6. ✅ Scripts de collecte reproductibles

---

**Bon travail sur votre projet de cybersécurité ! 🚀**
