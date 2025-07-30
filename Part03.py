from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from scapy.layers.dot11 import Dot11
from datetime import datetime
import matplotlib.pyplot as plt
from collections import defaultdict
import threading
import time
import platform

# Variables globales
suspicious_packet_stats = defaultdict(int)
log_file = "packets_log.txt"
suspicious_activities = []
start_time = time.time()

# Fonction de journalisation
def log_packet(pkt):
    with open(log_file, "a") as f:
        f.write(f"[{datetime.now()}] {pkt.summary()}\n")

# Détection de protocole
def get_packet_type(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(IP):
        return "IP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    elif pkt.haslayer(Dot11):
        return "Dot11"
    else:
        return "OTHER"

# Mise à jour des statistiques des paquets suspects
def update_suspicious_stats(pkt):
    proto = get_packet_type(pkt)
    suspicious_packet_stats[proto] += 1

# Fonction de rappel
def sniff_packets(pkt):
    print(pkt.summary())
    log_packet(pkt)
    is_suspicious = detect_suspicious_activity(pkt)
    if is_suspicious:
        update_suspicious_stats(pkt)

# Détection d'activités suspectes
def detect_suspicious_activity(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(HTTPRequest):
        uri = pkt[HTTPRequest].Path
        if "malicious" in uri or "exploit" in uri:
            suspicious_activities.append(f"Suspicious HTTP request: {uri}")
            print(f"[SUSPICIOUS] {uri}")
            return True

    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt[ICMP].code == 0:
        suspicious_activities.append(f"ICMP Echo Request from {pkt[IP].src}")
        print(f"[SUSPICIOUS] ICMP Echo Request from {pkt[IP].src}")
        return True

    if pkt.haslayer(TCP) and pkt[TCP].dport in [22, 23, 25, 110, 143, 993, 995, 587, 3389]:
        suspicious_activities.append(f"Suspicious TCP connection to port {pkt[TCP].dport} from {pkt[IP].src}")
        print(f"[SUSPICIOUS] TCP connection to port {pkt[TCP].dport} from {pkt[IP].src}")
        return True

    # Détection d'attaques Wi-Fi (exemple: deauthentication attack)
    if pkt.haslayer(Dot11) and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 12:
        suspicious_activities.append(f"Wi-Fi Deauthentication Attack from {pkt[Dot11].addr2}")
        print(f"[SUSPICIOUS] Wi-Fi Deauthentication Attack from {pkt[Dot11].addr2}")
        return True

    return False

# Thread de traçage en direct (optionnel)
def plot_suspicious_stats_live(interval=5):
    while True:
        time.sleep(interval)
        plt.clf()
        keys = list(suspicious_packet_stats.keys())
        values = [suspicious_packet_stats[k] for k in keys]
        plt.bar(keys, values, color='red')
        plt.title("Statistiques des paquets suspects capturés")
        plt.xlabel("Protocoles")
        plt.ylabel("Nombre de paquets")
        plt.tight_layout()
        plt.pause(0.01)

# Configuration du sniffer
def start_sniffing():
    print("[*] Démarrage de la capture...")
    iface = "wlan0" if platform.system() == "Linux" else "Wi-Fi"
    try:
        sniff(prn=sniff_packets, iface=iface, store=False)
    except Exception as e:
        print(f"[ERROR] Impossible de capturer les paquets sur l'interface {iface}: {e}")
        print("[INFO] Veuillez vérifier que l'interface réseau est correcte et que vous avez les permissions nécessaires.")

# Exécution principale
if __name__ == "__main__":
    # Lancer la visualisation dans un thread
    plt.ion()
    threading.Thread(target=plot_suspicious_stats_live, daemon=True).start()

    # Démarrer le sniffer
    start_sniffing()