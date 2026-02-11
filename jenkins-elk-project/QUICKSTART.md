# 🚀 Quick Start - Jenkins Security Dataset avec ELK Stack

## Installation en 5 minutes

### 1. Préparer l'environnement
```bash
# Créer le dossier du projet
mkdir jenkins-security-dataset
cd jenkins-security-dataset

# Créer les dossiers nécessaires
mkdir -p scripts attack_scripts dataset/{logs,output}

# Télécharger les fichiers de configuration :
# - docker-compose.yml
# - jenkins-logging.properties
# - filebeat.yml
```

### 2. Démarrer l'infrastructure ELK + Jenkins
```bash
# Démarrer tous les services
docker-compose up -d

# Vérifier que tout est démarré
docker-compose ps

# Vous devriez voir :
# - elasticsearch (port 9200)
# - kibana (port 5601)
# - jenkins (port 8080)
# - filebeat (collecteur)
```

### 3. Vérifier que les services sont prêts
```bash
# Vérifier Elasticsearch
curl http://localhost:9200/_cluster/health

# Vérifier Kibana (attendre 1-2 minutes)
curl http://localhost:5601/api/status

# Vérifier Jenkins (attendre 2-3 minutes)
curl http://localhost:8080
```

### 4. Configuration initiale de Jenkins
```bash
# Obtenir le mot de passe admin initial
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword

# Accéder à Jenkins : http://localhost:8080
# - Coller le mot de passe
# - Installer les plugins recommandés
# - Créer un compte admin (username: admin, password: admin)
```

### 5. Vérifier la collecte des logs dans Kibana

#### Accéder à Kibana
```
URL: http://localhost:5601
```

#### Créer un Index Pattern
1. Menu (☰) → **Stack Management** → **Index Patterns**
2. Cliquer sur **Create index pattern**
3. Index pattern name : `filebeat-*`
4. Time field : `@timestamp`
5. Cliquer sur **Create index pattern**

#### Visualiser les logs Jenkins
1. Menu (☰) → **Discover**
2. Sélectionner l'index pattern `filebeat-*`
3. Vous devriez voir les logs Jenkins en temps réel

#### Filtrer uniquement Jenkins
Dans la barre de recherche KQL :
```kql
container.name: "jenkins"
```

### 6. Vérifier les logs FINEST
Dans Kibana Discover, rechercher :
```kql
container.name: "jenkins" AND log.level: "FINEST"
```

Vous devriez voir des logs très détaillés comme :
```
FINEST hudson.model.Queue maintain
FINEST jenkins.model.Jenkins getQueue
```

**Si vous ne voyez pas de logs FINEST**, redémarrer Jenkins :
```bash
docker-compose restart jenkins
# Attendre 2 minutes puis vérifier à nouveau
```

### 7. Collecter le dataset complet

#### Option A : Collecte automatique (RECOMMANDÉE)
```bash
# Lance tout automatiquement :
# - 1h de trafic normal (10 users)
# - Toutes les attaques
# - Export et transformation MITRE CAR
python3 scripts/collect_dataset.py \
  --jenkins-url http://localhost:8080 \
  --normal-duration 3600 \
  --normal-users 10 \
  --backend elasticsearch

# Dataset final : dataset/output/jenkins-logs-mitre-car.json
```

#### Option B : Collecte manuelle étape par étape
```bash
# 1. Trafic normal (1 heure)
python3 scripts/generate_normal_traffic.py \
  --target http://localhost:8080 \
  --users 10 \
  --duration 3600

# 2. Attaques (après le trafic normal)
python3 attack_scripts/brute_force.py \
  --target http://localhost:8080 \
  --duration 300

sleep 60

python3 attack_scripts/xxe_injection.py \
  --target http://localhost:8080 \
  --user admin \
  --password admin \
  --duration 300

sleep 60

python3 attack_scripts/rce_script_console.py \
  --target http://localhost:8080 \
  --user admin \
  --password admin \
  --attack-type all

# 3. Export depuis Elasticsearch
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

# 4. Transformer en MITRE CAR
python3 scripts/transform_to_mitre_car.py \
  --input dataset/logs/jenkins-logs-raw.json \
  --output dataset/output/jenkins-logs-mitre-car.json \
  --annotate
```

## 📊 Requêtes Kibana utiles

### Discover - Barre de recherche KQL

**Tous les logs Jenkins :**
```kql
container.name: "jenkins"
```

**Authentifications échouées (Brute Force) :**
```kql
container.name: "jenkins" AND message: "authentication failed"
```

**Script Console (RCE) :**
```kql
container.name: "jenkins" AND (message: "script console" OR message: "groovy")
```

**Tentatives XXE :**
```kql
container.name: "jenkins" AND (message: "<!ENTITY" OR message: "<!DOCTYPE" OR message: "SYSTEM")
```

**Logs de niveau WARNING ou SEVERE :**
```kql
container.name: "jenkins" AND (log.level: "WARNING" OR log.level: "SEVERE")
```

**Timeline horaire des logs :**
```kql
container.name: "jenkins"
```
Puis ajuster l'intervalle de temps en haut à droite (par ex. Last 1 hour)

## 🎨 Créer des visualisations dans Kibana

### 1. Dashboard d'attaques

**Menu → Dashboard → Create dashboard → Create visualization**

#### Graphique 1 : Tentatives d'authentification dans le temps
- Type : **Line**
- Metrics : Count
- Buckets : 
  - X-axis : Date Histogram sur `@timestamp`
  - Split series : Filters
    - Filter 1: `message: "authentication failed"` (label: Failed)
    - Filter 2: `message: "authentication success"` (label: Success)

#### Graphique 2 : Top des types d'événements
- Type : **Pie**
- Metrics : Count
- Buckets : Split slices sur `log.level`

#### Graphique 3 : Activité Script Console
- Type : **Metric**
- Metrics : Count
- Add filter : `message: "script console"`

### 2. Sauvegarder le dashboard
- Cliquer sur **Save**
- Nom : "Jenkins Security Monitoring"

## 🛡️ Créer des règles de détection

### Menu → Security → Rules → Detection rules → Create new rule

#### Règle 1 : Brute Force Detection
```
Rule type: Custom query
Index pattern: filebeat-*

Query:
container.name: "jenkins" AND message: "authentication failed"

Conditions:
- When number of matches is above 10
- In a 5 minute window

Actions:
- Send email / webhook / etc.
```

#### Règle 2 : Script Console Access
```
Rule type: Custom query
Index pattern: filebeat-*

Query:
container.name: "jenkins" AND (message: "script console" OR message: "groovy")

Conditions:
- When query returns at least 1 result

Severity: High
```

#### Règle 3 : XXE Injection Attempt
```
Rule type: Custom query
Index pattern: filebeat-*

Query:
container.name: "jenkins" AND (message: "<!ENTITY" OR message: "<!DOCTYPE")

Conditions:
- When query returns at least 1 result

Severity: Critical
```

## 🐛 Dépannage

### Les logs n'apparaissent pas dans Kibana

**1. Vérifier que Filebeat collecte les logs**
```bash
# Voir les logs de Filebeat
docker logs filebeat

# Vous devriez voir des lignes comme :
# "Harvester started for file"
# "Non-zero metrics in the last 30s"
```

**2. Vérifier qu'Elasticsearch reçoit les données**
```bash
# Lister les indices
curl http://localhost:9200/_cat/indices?v

# Vous devriez voir des indices filebeat-*
```

**3. Vérifier que Jenkins produit bien des logs FINEST**
```bash
# Voir les logs Jenkins
docker logs jenkins 2>&1 | grep FINEST | head -20

# Si vous ne voyez pas FINEST, vérifier la config
docker exec jenkins cat /var/jenkins_home/logging.properties
```

### Jenkins ne démarre pas
```bash
docker logs jenkins
docker-compose restart jenkins
```

### Elasticsearch est lent ou plante
```bash
# Vérifier la mémoire allouée dans docker-compose.yml
# ES_JAVA_OPTS doit être : -Xms2g -Xmx2g minimum

# Augmenter si nécessaire et redémarrer
docker-compose down
docker-compose up -d
```

### Recréer l'index pattern
```bash
# Si l'index pattern ne fonctionne pas
# Dans Kibana :
# Stack Management → Index Patterns → Supprimer filebeat-*
# Puis recréer avec les étapes ci-dessus
```

## 📁 Structure des données dans Elasticsearch

Les logs Jenkins sont stockés avec cette structure :
```json
{
  "@timestamp": "2024-02-11T10:15:23.000Z",
  "container": {
    "name": "jenkins",
    "id": "abc123..."
  },
  "message": "FINEST hudson.model.Queue maintain",
  "log": {
    "level": "FINEST"
  },
  "stream": "stdout"
}
```

## 📚 Prochaines étapes

1. ✅ Vérifier les logs dans Kibana
2. ✅ Créer des dashboards
3. ✅ Configurer les règles de détection
4. ✅ Collecter le dataset avec les scripts Python
5. ✅ Transformer au format MITRE CAR
6. ✅ Analyser et documenter les résultats

## 🎯 Points de vérification

- [ ] Elasticsearch répond sur http://localhost:9200
- [ ] Kibana accessible sur http://localhost:5601
- [ ] Jenkins accessible sur http://localhost:8080
- [ ] Index pattern `filebeat-*` créé dans Kibana
- [ ] Logs Jenkins visibles dans Discover
- [ ] Logs au niveau FINEST présents
- [ ] Scripts Python fonctionnels

---

**Votre infrastructure ELK + Jenkins est prête ! 🚀**

Pour plus de détails, consulter **README.md**
