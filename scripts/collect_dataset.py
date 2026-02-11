#!/usr/bin/env python3
"""
Script d'orchestration de la collecte du dataset Jenkins
Automatise la collecte des logs pour les scénarios normaux et malveillants
"""

import subprocess
import time
import argparse
import json
from datetime import datetime
import os

class DatasetCollector:
    def __init__(self, jenkins_url="http://localhost:8080"):
        self.jenkins_url = jenkins_url
        self.logs_dir = "./dataset/logs"
        self.output_dir = "./dataset/output"
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        
    def log(self, message):
        """Affiche un message avec timestamp"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")
    
    def run_command(self, command, description):
        """Exécute une commande et log le résultat"""
        self.log(f"Exécution: {description}")
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.log(f"✓ Succès: {description}")
                return True
            else:
                self.log(f"✗ Erreur: {description}")
                self.log(f"  {result.stderr}")
                return False
        except Exception as e:
            self.log(f"✗ Exception: {e}")
            return False
    
    def wait_for_jenkins(self):
        """Attend que Jenkins soit prêt"""
        self.log("Attente de Jenkins...")
        max_attempts = 30
        for i in range(max_attempts):
            try:
                import requests
                response = requests.get(self.jenkins_url, timeout=5)
                if response.status_code in [200, 403]:
                    self.log("✓ Jenkins est prêt")
                    return True
            except:
                pass
            time.sleep(10)
        self.log("✗ Jenkins n'a pas démarré à temps")
        return False
    
    def phase_normal_traffic(self, duration=3600, users=10):
        """Phase 1: Génération de trafic normal"""
        self.log("=" * 60)
        self.log("PHASE 1: TRAFIC NORMAL")
        self.log("=" * 60)
        
        command = f"python3 scripts/generate_normal_traffic.py --target {self.jenkins_url} --users {users} --duration {duration}"
        return self.run_command(command, f"Génération trafic normal ({duration}s, {users} users)")
    
    def phase_attacks(self):
        """Phase 2: Exécution des attaques"""
        self.log("=" * 60)
        self.log("PHASE 2: ATTAQUES")
        self.log("=" * 60)
        
        attacks = [
            {
                'name': 'Brute Force',
                'script': 'attack_scripts/brute_force.py',
                'duration': 300,
                'args': '--duration 300 --delay 0.5'
            },
            {
                'name': 'XXE Injection',
                'script': 'attack_scripts/xxe_injection.py',
                'duration': 300,
                'args': '--duration 300 --attack-type all --user admin --password admin'
            },
            {
                'name': 'RCE Script Console',
                'script': 'attack_scripts/rce_script_console.py',
                'duration': 300,
                'args': '--attack-type all --user admin --password admin'
            }
        ]
        
        for attack in attacks:
            self.log(f"\n--- Attaque: {attack['name']} ---")
            command = f"python3 {attack['script']} --target {self.jenkins_url} {attack['args']}"
            self.run_command(command, attack['name'])
            
            # Pause entre les attaques
            self.log(f"Pause de 60 secondes avant l'attaque suivante...")
            time.sleep(60)
    
    def export_logs_from_loki(self, start_time, end_time):
        """Exporte les logs depuis Loki"""
        self.log("=" * 60)
        self.log("EXPORT DES LOGS DEPUIS LOKI")
        self.log("=" * 60)
        
        output_file = f"{self.logs_dir}/jenkins-logs-raw-{int(time.time())}.jsonl"
        
        # Utiliser logcli pour exporter les logs
        command = f"""logcli query '{{container_name="jenkins"}}' \
            --addr=http://localhost:3100 \
            --from="{start_time}" \
            --to="{end_time}" \
            --output=jsonl \
            --limit=1000000 > {output_file}"""
        
        if self.run_command(command, "Export Loki"):
            self.log(f"✓ Logs exportés vers: {output_file}")
            return output_file
        return None
    
    def export_logs_from_elasticsearch(self):
        """Exporte les logs depuis Elasticsearch"""
        self.log("=" * 60)
        self.log("EXPORT DES LOGS DEPUIS ELASTICSEARCH")
        self.log("=" * 60)
        
        output_file = f"{self.logs_dir}/jenkins-logs-raw-{int(time.time())}.json"
        
        command = f"""curl -X GET "localhost:9200/jenkins-logs-*/_search?size=10000" \
            -H 'Content-Type: application/json' \
            -d '{{
              "query": {{
                "match_all": {{}}
              }},
              "sort": [
                {{ "@timestamp": "asc" }}
              ]
            }}' > {output_file}"""
        
        if self.run_command(command, "Export Elasticsearch"):
            self.log(f"✓ Logs exportés vers: {output_file}")
            return output_file
        return None
    
    def transform_to_mitre_car(self, input_file):
        """Transforme les logs au format MITRE CAR"""
        self.log("=" * 60)
        self.log("TRANSFORMATION MITRE CAR")
        self.log("=" * 60)
        
        output_file = f"{self.output_dir}/jenkins-logs-mitre-car-{int(time.time())}.json"
        
        command = f"python3 scripts/transform_to_mitre_car.py --input {input_file} --output {output_file} --annotate"
        
        if self.run_command(command, "Transformation MITRE CAR"):
            self.log(f"✓ Dataset MITRE CAR créé: {output_file}")
            return output_file
        return None
    
    def generate_statistics(self, mitre_car_file):
        """Génère des statistiques sur le dataset"""
        self.log("=" * 60)
        self.log("GÉNÉRATION DES STATISTIQUES")
        self.log("=" * 60)
        
        try:
            with open(mitre_car_file, 'r') as f:
                data = json.load(f)
            
            stats = {
                'total_events': data['metadata']['total_events'],
                'malicious_events': data['metadata']['malicious_events'],
                'benign_events': data['metadata']['benign_events'],
                'attack_types': {},
                'mitre_techniques': {}
            }
            
            for event in data['events']:
                if event['metadata']['is_malicious']:
                    attack_type = event['metadata']['attack_type']
                    technique = event['metadata']['mitre_technique']
                    
                    stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1
                    stats['mitre_techniques'][technique] = stats['mitre_techniques'].get(technique, 0) + 1
            
            stats_file = f"{self.output_dir}/dataset-statistics.json"
            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
            
            self.log("\n=== STATISTIQUES DU DATASET ===")
            self.log(f"Total événements: {stats['total_events']}")
            self.log(f"Événements malveillants: {stats['malicious_events']}")
            self.log(f"Événements bénins: {stats['benign_events']}")
            self.log("\nTypes d'attaques:")
            for attack_type, count in stats['attack_types'].items():
                self.log(f"  - {attack_type}: {count}")
            self.log("\nTechniques MITRE ATT&CK:")
            for technique, count in stats['mitre_techniques'].items():
                self.log(f"  - {technique}: {count}")
            
            return stats_file
            
        except Exception as e:
            self.log(f"✗ Erreur génération statistiques: {e}")
            return None
    
    def collect_full_dataset(self, normal_duration=3600, normal_users=10, use_loki=True):
        """Collecte complète du dataset"""
        self.log("=" * 80)
        self.log("DÉBUT DE LA COLLECTE DU DATASET JENKINS")
        self.log("=" * 80)
        
        start_collection = datetime.now()
        
        # 1. Vérifier que Jenkins est prêt
        if not self.wait_for_jenkins():
            return False
        
        # 2. Phase trafic normal
        if not self.phase_normal_traffic(normal_duration, normal_users):
            self.log("⚠ Avertissement: Problème avec le trafic normal")
        
        # Pause entre phases
        self.log("\nPause de 5 minutes entre les phases...")
        time.sleep(300)
        
        # 3. Phase attaques
        attack_start = datetime.now()
        self.phase_attacks()
        attack_end = datetime.now()
        
        # Pause pour laisser les logs se propager
        self.log("\nAttente de 2 minutes pour la propagation des logs...")
        time.sleep(120)
        
        # 4. Export des logs
        if use_loki:
            raw_logs = self.export_logs_from_loki(
                start_collection.isoformat() + 'Z',
                attack_end.isoformat() + 'Z'
            )
        else:
            raw_logs = self.export_logs_from_elasticsearch()
        
        if not raw_logs:
            self.log("✗ Erreur: Impossible d'exporter les logs")
            return False
        
        # 5. Transformation MITRE CAR
        mitre_car_file = self.transform_to_mitre_car(raw_logs)
        if not mitre_car_file:
            self.log("✗ Erreur: Transformation MITRE CAR échouée")
            return False
        
        # 6. Génération des statistiques
        stats_file = self.generate_statistics(mitre_car_file)
        
        end_collection = datetime.now()
        duration = (end_collection - start_collection).total_seconds()
        
        self.log("=" * 80)
        self.log("✓ COLLECTE DU DATASET TERMINÉE AVEC SUCCÈS")
        self.log("=" * 80)
        self.log(f"Durée totale: {duration/60:.1f} minutes")
        self.log(f"\nFichiers générés:")
        self.log(f"  - Logs bruts: {raw_logs}")
        self.log(f"  - Dataset MITRE CAR: {mitre_car_file}")
        if stats_file:
            self.log(f"  - Statistiques: {stats_file}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description="Orchestration de la collecte du dataset Jenkins")
    parser.add_argument('--jenkins-url', default='http://localhost:8080',
                        help='URL de Jenkins')
    parser.add_argument('--normal-duration', type=int, default=3600,
                        help='Durée du trafic normal en secondes (défaut: 1h)')
    parser.add_argument('--normal-users', type=int, default=10,
                        help='Nombre d\'utilisateurs simultanés pour le trafic normal')
    parser.add_argument('--backend', choices=['loki', 'elasticsearch'], default='loki',
                        help='Backend de logs à utiliser')
    
    args = parser.parse_args()
    
    collector = DatasetCollector(args.jenkins_url)
    
    success = collector.collect_full_dataset(
        normal_duration=args.normal_duration,
        normal_users=args.normal_users,
        use_loki=(args.backend == 'loki')
    )
    
    exit(0 if success else 1)

if __name__ == "__main__":
    main()
