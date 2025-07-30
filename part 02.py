from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import os

# Paramètres globaux
INTERFACE = "Wi-Fi"  # À adapter selon votre interface sous Windows (ex: "Ethernet", "Wi-Fi")
FILTRE = "ip"        # Exemple : "port 80", "arp", "ip"
DUREE_CAPTURE = 60   # En secondes
ROTATION_LOGS = 3    # Nombre de fichiers de log à générer avant arrêt
PAQUETS_PAR_FICHIER = 100  # Limite de paquets par fichier

# Variables globales
packet_list = []
arp_scan_counter = {}
output_dir = "logs_scapy"
os.makedirs(output_dir, exist_ok=True)

def detect_anomalie(pkt):
    """Détection simple d'anomalies type scan ARP ou SYN flood"""
    if ARP in pkt:
        ip_source = pkt[ARP].psrc
        arp_scan_counter[ip_source] = arp_scan_counter.get(ip_source, 0) + 1
        if arp_scan_counter[ip_source] > 10:
            print(f"[ Alerte] ARP scan suspect détecté depuis {ip_source}")

    elif TCP in pkt and pkt[TCP].flags == "S":
        print(f"[ Alerte] Tentative SYN flood de {pkt[IP].src} vers {pkt[IP].dst}")

def process_packet(pkt):
    packet_list.append(pkt)
    detect_anomalie(pkt)
    print(pkt.summary())

def exporter_csv(packet_list, log_index):
    """Exporter les paquets sous forme de DataFrame CSV"""
    data = []
    for pkt in packet_list:
        data.append({
            "timestamp": pkt.time,
            "src": pkt[IP].src if IP in pkt else "",
            "dst": pkt[IP].dst if IP in pkt else "",
            "proto": pkt.proto if IP in pkt else "",
            "length": len(pkt)
        })

    df = pd.DataFrame(data)
    csv_file = os.path.join(output_dir, f"log_{log_index}.csv")
    df.to_csv(csv_file, index=False)
    print(f"[ Export] Fichier CSV sauvegardé : {csv_file}")
    return df

def affichage_stats(df):
    """Afficher un graphique matplotlib du nombre de paquets par IP source"""
    if df.empty: return
    stats = df['src'].value_counts().head(10)
    stats.plot(kind='barh', title="Top IP Sources", color='skyblue')
    plt.xlabel("Nombre de paquets")
    plt.ylabel("Adresse IP source")
    plt.tight_layout()
    plt.show()

def capture_rotative():
    """Capture par lots avec rotation et sauvegarde"""
    for i in range(ROTATION_LOGS):
        print(f"\n[ Capture {i+1}/{ROTATION_LOGS}] en cours...")
        global packet_list
        packet_list = []
        sniff(iface=INTERFACE, prn=process_packet, filter=FILTRE, timeout=DUREE_CAPTURE, count=PAQUETS_PAR_FICHIER)
        df = exporter_csv(packet_list, i+1)
        affichage_stats(df)

if __name__ == "__main__":
    print("[Démarrage de la surveillance Scapy sur Windows]")
    capture_rotative()
