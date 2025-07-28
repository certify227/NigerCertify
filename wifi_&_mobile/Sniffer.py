
from scapy.all import *  
sniff(prn=lambda x: x.summary(), count=10)  
