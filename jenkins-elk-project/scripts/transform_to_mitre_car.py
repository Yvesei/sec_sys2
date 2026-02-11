#!/usr/bin/env python3
"""
Script de transformation des logs Jenkins au format MITRE CAR
Convertit les logs bruts en format MITRE Cyber Analytics Repository
"""

import json
import re
import argparse
from datetime import datetime
from typing import Dict, List, Any
import hashlib

class MITRECARTransformer:
    def __init__(self):
        self.attack_patterns = {
            'brute_force': {
                'pattern': r'authentication failed|login failed|incorrect password',
                'technique': 'T1110.001',
                'tactic': 'Credential Access'
            },
            'xxe_injection': {
                'pattern': r'<!ENTITY|<!DOCTYPE|SYSTEM "file:|SYSTEM "http:',
                'technique': 'T1203',
                'tactic': 'Execution'
            },
            'rce_script_console': {
                'pattern': r'script console|groovy|execute\(\)|Runtime\.exec',
                'technique': 'T1059.007',
                'tactic': 'Execution'
            },
            'path_traversal': {
                'pattern': r'\.\./|\.\./\.\.|%2e%2e',
                'technique': 'T1083',
                'tactic': 'Discovery'
            },
            'privilege_escalation': {
                'pattern': r'sudo|SUID|setuid|privilege|escalation',
                'technique': 'T1068',
                'tactic': 'Privilege Escalation'
            }
        }
    
    def parse_jenkins_log(self, log_line: str) -> Dict[str, Any]:
        """Parse une ligne de log Jenkins"""
        # Format typique: Dec 11, 2024 10:15:23 AM FINEST hudson.model.Queue maintain
        timestamp_pattern = r'(\w{3} \d{1,2}, \d{4} \d{1,2}:\d{2}:\d{2} [AP]M)'
        level_pattern = r'(FINEST|FINER|FINE|CONFIG|INFO|WARNING|SEVERE)'
        logger_pattern = r'([\w\.]+)'
        
        match = re.match(
            f'{timestamp_pattern}\\s+{level_pattern}\\s+{logger_pattern}\\s+(.+)',
            log_line
        )
        
        if match:
            timestamp_str, level, logger, message = match.groups()
            timestamp = datetime.strptime(timestamp_str, '%b %d, %Y %I:%M:%S %p')
            
            return {
                'timestamp': timestamp.isoformat() + 'Z',
                'level': level,
                'logger': logger,
                'message': message.strip(),
                'raw': log_line
            }
        
        # Si le parsing échoue, retourner un format minimal
        return {
            'timestamp': datetime.now().isoformat() + 'Z',
            'level': 'INFO',
            'logger': 'unknown',
            'message': log_line,
            'raw': log_line
        }
    
    def detect_attack(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Détecte les patterns d'attaque dans un log"""
        message = log_entry.get('message', '').lower()
        
        for attack_type, config in self.attack_patterns.items():
            if re.search(config['pattern'], message, re.IGNORECASE):
                return {
                    'is_malicious': True,
                    'attack_type': attack_type,
                    'mitre_technique': config['technique'],
                    'mitre_tactic': config['tactic'],
                    'confidence': 'high'
                }
        
        return {
            'is_malicious': False,
            'attack_type': None,
            'mitre_technique': None,
            'mitre_tactic': None,
            'confidence': None
        }
    
    def extract_network_info(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extrait les informations réseau du log"""
        message = log_entry.get('message', '')
        
        # Extraire les IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, message)
        
        # Extraire les URLs
        url_pattern = r'https?://[\w\-\.]+(?::\d+)?(?:/[\w\-\./?%&=]*)?'
        urls = re.findall(url_pattern, message)
        
        return {
            'source_ips': list(set(ips)) if ips else [],
            'urls': list(set(urls)) if urls else []
        }
    
    def transform_to_car(self, log_entry: Dict[str, Any], event_id: str) -> Dict[str, Any]:
        """Transforme un log en format MITRE CAR"""
        
        attack_info = self.detect_attack(log_entry)
        network_info = self.extract_network_info(log_entry)
        
        car_event = {
            'event_id': event_id,
            'version': '1.0',
            'timestamp': log_entry.get('timestamp'),
            
            # Source de l'événement
            'source': {
                'type': 'application',
                'name': 'jenkins',
                'component': log_entry.get('logger', 'unknown'),
                'host': 'jenkins-container'
            },
            
            # Action observée
            'action': {
                'type': self._infer_action_type(log_entry),
                'result': self._infer_action_result(log_entry),
                'description': log_entry.get('message', '')
            },
            
            # Acteur (si détectable)
            'actor': {
                'user': self._extract_user(log_entry),
                'ip': network_info['source_ips'][0] if network_info['source_ips'] else None
            },
            
            # Cible de l'action
            'target': {
                'resource': self._extract_resource(log_entry),
                'type': 'jenkins-instance'
            },
            
            # Métadonnées de sécurité
            'metadata': {
                'log_level': log_entry.get('level'),
                'is_malicious': attack_info['is_malicious'],
                'attack_type': attack_info['attack_type'],
                'mitre_technique': attack_info['mitre_technique'],
                'mitre_tactic': attack_info['mitre_tactic'],
                'confidence': attack_info['confidence'],
                'urls': network_info['urls'],
                'raw_log': log_entry.get('raw')
            }
        }
        
        return car_event
    
    def _infer_action_type(self, log_entry: Dict[str, Any]) -> str:
        """Infère le type d'action à partir du log"""
        message = log_entry.get('message', '').lower()
        
        if 'authentication' in message or 'login' in message:
            return 'authentication-attempt'
        elif 'script' in message or 'execute' in message:
            return 'code-execution'
        elif 'file' in message or 'read' in message:
            return 'file-access'
        elif 'create' in message or 'build' in message:
            return 'resource-creation'
        elif 'config' in message:
            return 'configuration-change'
        else:
            return 'unknown'
    
    def _infer_action_result(self, log_entry: Dict[str, Any]) -> str:
        """Infère le résultat de l'action"""
        message = log_entry.get('message', '').lower()
        level = log_entry.get('level', '')
        
        if 'failed' in message or 'error' in message or level in ['SEVERE', 'WARNING']:
            return 'failure'
        elif 'success' in message or 'completed' in message:
            return 'success'
        else:
            return 'unknown'
    
    def _extract_user(self, log_entry: Dict[str, Any]) -> str:
        """Extrait le nom d'utilisateur du log"""
        message = log_entry.get('message', '')
        
        # Pattern pour extraire les noms d'utilisateurs
        user_patterns = [
            r'user[:\s]+(\w+)',
            r'by\s+(\w+)',
            r'for\s+(\w+)'
        ]
        
        for pattern in user_patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'unknown'
    
    def _extract_resource(self, log_entry: Dict[str, Any]) -> str:
        """Extrait la ressource ciblée"""
        message = log_entry.get('message', '')
        
        # Extraire les chemins de fichiers ou URLs
        path_pattern = r'(/[\w\-\./]+)'
        match = re.search(path_pattern, message)
        if match:
            return match.group(1)
        
        return 'jenkins-instance'
    
    def process_logs(self, input_file: str, output_file: str, annotate: bool = False):
        """Traite un fichier de logs et génère le format MITRE CAR"""
        
        print(f"[{datetime.now()}] Début de la transformation MITRE CAR")
        print(f"  - Fichier d'entrée: {input_file}")
        print(f"  - Fichier de sortie: {output_file}")
        print(f"  - Annotation: {annotate}")
        
        car_events = []
        total_logs = 0
        malicious_count = 0
        
        with open(input_file, 'r') as f_in:
            for line_num, line in enumerate(f_in, 1):
                line = line.strip()
                if not line:
                    continue
                
                total_logs += 1
                
                # Parser le log
                log_entry = self.parse_jenkins_log(line)
                
                # Générer un event ID unique
                event_id = hashlib.md5(f"{line_num}-{line}".encode()).hexdigest()
                
                # Transformer en format CAR
                car_event = self.transform_to_car(log_entry, event_id)
                
                # Compter les événements malveillants
                if car_event['metadata']['is_malicious']:
                    malicious_count += 1
                
                car_events.append(car_event)
                
                if line_num % 1000 == 0:
                    print(f"  - Traité {line_num} logs...")
        
        # Sauvegarder en JSON
        with open(output_file, 'w') as f_out:
            json.dump({
                'metadata': {
                    'version': '1.0',
                    'generated_at': datetime.now().isoformat() + 'Z',
                    'source': 'jenkins-logs',
                    'total_events': len(car_events),
                    'malicious_events': malicious_count,
                    'benign_events': len(car_events) - malicious_count
                },
                'events': car_events
            }, f_out, indent=2)
        
        print(f"\n[{datetime.now()}] Transformation terminée")
        print(f"  - Total événements: {total_logs}")
        print(f"  - Événements malveillants: {malicious_count}")
        print(f"  - Événements bénins: {total_logs - malicious_count}")
        print(f"  - Fichier de sortie: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Transformation des logs Jenkins en format MITRE CAR")
    parser.add_argument('--input', required=True,
                        help='Fichier de logs d\'entrée')
    parser.add_argument('--output', required=True,
                        help='Fichier JSON de sortie (format MITRE CAR)')
    parser.add_argument('--annotate', action='store_true',
                        help='Annoter automatiquement les attaques détectées')
    
    args = parser.parse_args()
    
    transformer = MITRECARTransformer()
    transformer.process_logs(args.input, args.output, args.annotate)

if __name__ == "__main__":
    main()
