#!/usr/bin/env python3
"""
Script de génération de trafic légitime sur Jenkins
Simule l'utilisation normale de Jenkins par plusieurs utilisateurs
"""

import requests
import time
import random
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json

class JenkinsNormalUser:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False
        
    def authenticate(self):
        """Authentification légitime"""
        try:
            # Obtenir le crumb (CSRF token)
            crumb_url = f"{self.base_url}/crumbIssuer/api/json"
            response = self.session.get(crumb_url, auth=(self.username, self.password))
            if response.status_code == 200:
                crumb_data = response.json()
                self.session.headers.update({
                    crumb_data['crumbRequestField']: crumb_data['crumb']
                })
                self.authenticated = True
                print(f"[{datetime.now()}] {self.username} - Authentification réussie")
                return True
        except Exception as e:
            print(f"[{datetime.now()}] {self.username} - Erreur d'authentification: {e}")
        return False
    
    def visit_homepage(self):
        """Visite de la page d'accueil"""
        try:
            response = self.session.get(self.base_url)
            print(f"[{datetime.now()}] {self.username} - Visite page d'accueil [HTTP {response.status_code}]")
            time.sleep(random.uniform(0.5, 2))
        except Exception as e:
            print(f"[{datetime.now()}] {self.username} - Erreur visite homepage: {e}")
    
    def list_jobs(self):
        """Liste les jobs disponibles"""
        try:
            response = self.session.get(f"{self.base_url}/api/json")
            if response.status_code == 200:
                data = response.json()
                jobs = data.get('jobs', [])
                print(f"[{datetime.now()}] {self.username} - Liste {len(jobs)} jobs")
                time.sleep(random.uniform(1, 3))
        except Exception as e:
            print(f"[{datetime.now()}] {self.username} - Erreur liste jobs: {e}")
    
    def view_job(self, job_name):
        """Consulte un job spécifique"""
        try:
            response = self.session.get(f"{self.base_url}/job/{job_name}/")
            print(f"[{datetime.now()}] {self.username} - Consulte job '{job_name}' [HTTP {response.status_code}]")
            time.sleep(random.uniform(2, 5))
        except Exception as e:
            print(f"[{datetime.now()}] {self.username} - Erreur consultation job: {e}")
    
    def trigger_build(self, job_name):
        """Déclenche un build"""
        if not self.authenticated:
            return
        try:
            response = self.session.post(f"{self.base_url}/job/{job_name}/build")
            print(f"[{datetime.now()}] {self.username} - Build déclenché '{job_name}' [HTTP {response.status_code}]")
            time.sleep(random.uniform(1, 2))
        except Exception as e:
            print(f"[{datetime.now()}] {self.username} - Erreur déclenchement build: {e}")
    
    def view_build_console(self, job_name, build_number):
        """Consulte la console d'un build"""
        try:
            response = self.session.get(f"{self.base_url}/job/{job_name}/{build_number}/console")
            print(f"[{datetime.now()}] {self.username} - Console build #{build_number} [HTTP {response.status_code}]")
            time.sleep(random.uniform(3, 6))
        except Exception as e:
            print(f"[{datetime.now()}] {self.username} - Erreur consultation console: {e}")
    
    def view_configure(self, job_name):
        """Consulte la configuration d'un job"""
        if not self.authenticated:
            return
        try:
            response = self.session.get(f"{self.base_url}/job/{job_name}/configure")
            print(f"[{datetime.now()}] {self.username} - Configuration '{job_name}' [HTTP {response.status_code}]")
            time.sleep(random.uniform(2, 4))
        except Exception as e:
            print(f"[{datetime.now()}] {self.username} - Erreur consultation config: {e}")

def simulate_user_session(base_url, user_id, duration, credentials=None):
    """Simule une session utilisateur complète"""
    if credentials:
        username, password = credentials
    else:
        username = f"user{user_id}"
        password = "password"
    
    user = JenkinsNormalUser(base_url, username, password)
    
    # Authentification
    user.authenticate()
    
    start_time = time.time()
    actions = [
        user.visit_homepage,
        user.list_jobs,
        lambda: user.view_job("test-job-1"),
        lambda: user.view_job("test-job-2"),
        lambda: user.view_build_console("test-job-1", 1),
        lambda: user.view_configure("test-job-1"),
        lambda: user.trigger_build("test-job-1"),
    ]
    
    while time.time() - start_time < duration:
        # Sélectionner une action aléatoire
        action = random.choice(actions)
        try:
            action()
        except Exception as e:
            print(f"[{datetime.now()}] Erreur lors de l'action: {e}")
        
        # Pause entre les actions (comportement humain)
        time.sleep(random.uniform(5, 15))
    
    print(f"[{datetime.now()}] {username} - Session terminée")

def main():
    parser = argparse.ArgumentParser(description="Génération de trafic légitime sur Jenkins")
    parser.add_argument('--target', default='http://localhost:8080', help='URL de Jenkins')
    parser.add_argument('--users', type=int, default=5, help='Nombre d\'utilisateurs simultanés')
    parser.add_argument('--duration', type=int, default=3600, help='Durée en secondes')
    parser.add_argument('--credentials', help='Fichier JSON avec les credentials')
    
    args = parser.parse_args()
    
    print(f"[{datetime.now()}] Démarrage de la génération de trafic normal")
    print(f"  - Cible: {args.target}")
    print(f"  - Utilisateurs: {args.users}")
    print(f"  - Durée: {args.duration}s ({args.duration/60:.1f} minutes)")
    
    # Charger les credentials si fournis
    credentials_list = []
    if args.credentials:
        with open(args.credentials, 'r') as f:
            credentials_list = json.load(f)
    
    # Lancer les utilisateurs en parallèle
    with ThreadPoolExecutor(max_workers=args.users) as executor:
        futures = []
        for i in range(args.users):
            creds = credentials_list[i] if i < len(credentials_list) else None
            future = executor.submit(simulate_user_session, args.target, i+1, args.duration, creds)
            futures.append(future)
        
        # Attendre la fin de toutes les sessions
        for future in futures:
            future.result()
    
    print(f"[{datetime.now()}] Génération de trafic terminée")

if __name__ == "__main__":
    main()
