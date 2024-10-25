# Xifi-
A simple script that can help you to make something great.

# Wi-Fi Handshake Capture and Crack Script

Ce script permet de scanner les réseaux Wi-Fi disponibles, de déconnecter tous les clients d'un réseau spécifique, de capturer un handshake WPA/WPA2 et de tenter automatiquement de cracker le mot de passe Wi-Fi en utilisant une wordlist. Ce script est conçu pour fonctionner sur des distributions Linux telles que Kali Linux avec les outils nécessaires installés.

## Fonctionnalités

- **Scan des réseaux Wi-Fi** : Le script utilise `scapy` pour scanner et afficher les réseaux Wi-Fi disponibles.
- **Déconnexion des clients** : Il déconnecte tous les clients d'un réseau choisi en envoyant des paquets de désauthentification.
- **Capture du handshake WPA/WPA2** : Il écoute les reconnects des clients pour capturer le handshake.
- **Crackage automatique** : Après la capture du handshake, le script utilise `aircrack-ng` pour tenter de cracker le mot de passe du réseau à l'aide d'une wordlist.

## Prérequis

Avant de lancer ce script, assurez-vous que votre système est configuré correctement :

1. **Python 3.x** installé.
2. Les bibliothèques suivantes doivent être installées :
   - `scapy`
   - `os` et `time` (incluses par défaut avec Python)
3. **Système Linux** avec une carte Wi-Fi compatible mode moniteur.
4. **aircrack-ng** installé pour le cracking du handshake.
5. Une **wordlist** pour tenter de cracker le mot de passe. Vous pouvez utiliser des wordlists comme celles de [SecLists](https://github.com/danielmiessler/SecLists).

### Installation des dépendances

Vous pouvez installer les dépendances Python avec la commande suivante :

```bash
pip install scapy

## sudo apt-get install aircrack-ng

## sudo airmon-ng start wlan0

## sudo python3 Xifi.py
