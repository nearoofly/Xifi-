# Version 0.1.4

from scapy.all import *
import os
import time
import subprocess
from colorama import Fore, Style, init

# Initialiser Colorama
init(autoreset=True)

def get_wifi_interface():
    """Détecte l'interface Wi-Fi active."""
    try:
        output = subprocess.check_output("iw dev | grep Interface", shell=True).decode().strip().split("\n")
        interfaces = [line.split()[1] for line in output]
        for iface in interfaces:
            if "wlan" in iface:
                return iface
    except Exception as e:
        print(Fore.RED + f"Erreur lors de la détection de l'interface Wi-Fi : {e}")
    return None

def setup_environment(interface):
    """Tuer les processus qui pourraient interférer et démarrer airmon-ng."""
    os.system("airmon-ng check kill")  # Tuer les processus
    os.system(f"airmon-ng start {interface}")  # Démarrer airmon-ng
    time.sleep(2)  # Attendre que le mode moniteur soit activé

def display_banner():
    """Affiche une bannière avec une image ASCII en couleur."""
    print(Fore.GREEN + """
     __        __              _           _       
     \\ \\      / /__  _ __ ___ | |__   __ _| |_ ___ 
      \\ \\ /\\ / / _ \\| '_ ` _ \\| '_ \\ / _` | __/ _ \\
       \\ V  V / (_) | | | | | | |_) | (_| | ||  __/
        \\_/\\_/ \\___/|_| |_| |_|_.__/ \\__,_|\\__\\___|
    """)
    print(Fore.YELLOW + "Auteur : Wharkly47 AKA Goofly")
    print(Fore.RED + "GitHub : https://github.com/nearofly")
    print(Fore.BLUE + "Version : 0.1.4\n")

def scan_networks():
    """Scanne les réseaux Wi-Fi disponibles."""
    print(Fore.YELLOW + "Scan des réseaux disponibles...")
    networks = []

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11].info.decode('utf-8', errors='ignore')
            bssid = packet[Dot11].addr2
            if (bssid, ssid) not in networks:
                networks.append((bssid, ssid))
                print(Fore.GREEN + f"Réseau trouvé : SSID : {ssid}, BSSID : {bssid}")

    # Utiliser un timeout plus long si nécessaire
    sniff(iface='wlan0mon', prn=packet_handler, timeout=60)  # Sniffer pour 60 secondes
    return networks

def capture_handshake(target_bssid):
    """Capture le handshake pour le réseau cible."""
    capture_dir = "captures"
    os.makedirs(capture_dir, exist_ok=True)

    # Démarrer airodump-ng pour capturer le handshake
    print(Fore.YELLOW + f"Démarrage de airodump-ng pour capturer le handshake de {target_bssid}...")
    airodump_command = f"airodump-ng --bssid {target_bssid} -c 6 --write {capture_dir}/capture wlan0mon"
    
    try:
        subprocess.Popen(airodump_command, shell=True)
    except Exception as e:
        print(Fore.RED + f"Erreur lors du démarrage de airodump-ng : {e}")

def main():
    interface = get_wifi_interface()
    if interface is None:
        print(Fore.RED + "Aucune interface Wi-Fi trouvée. Sortie.")
        return
    
    setup_environment(interface)  # Configurer l'environnement
    display_banner()  # Afficher la bannière
    
    # Scanner les réseaux
    networks = scan_networks()
    
    # Choisir un réseau
    if networks:
        print(Fore.YELLOW + "\nChoisissez un réseau pour capturer le handshake :")
        for i, (bssid, ssid) in enumerate(networks):
            print(Fore.GREEN + f"{i + 1}: SSID : {ssid}, BSSID : {bssid}")
        
        while True:
            try:
                choice = int(input(Fore.YELLOW + "Entrez le numéro du réseau : ")) - 1
                if 0 <= choice < len(networks):
                    target_bssid, target_ssid = networks[choice]
                    break
                else:
                    print(Fore.RED + "Choix invalide. Essayez à nouveau.")
            except ValueError:
                print(Fore.RED + "Veuillez entrer un nombre valide.")
        
        # Capturer le handshake
        capture_handshake(target_bssid)

        # Vous pouvez ajouter ici une logique pour attendre la capture du mot de passe
        print(Fore.YELLOW + f"Handshake capturé pour le réseau : SSID : {target_ssid}, BSSID : {target_bssid}.")
        
        # Pour arrêter airodump-ng, vous pouvez utiliser un signal ou une autre méthode
        # par exemple, attendre une entrée de l'utilisateur
        input(Fore.YELLOW + "Appuyez sur Entrée pour arrêter le script...")
    else:
        print(Fore.RED + "Aucun réseau trouvé :Contact Wharkly47 pour obtenir la version recente du logiciel. Mail: wharklya@gmail.com 
        
              Sortie.")

if __name__ == '__main__':
    main()
