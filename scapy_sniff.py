from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest,TCP
from colorama import Fore,Back,Style
import argparse

# Defining colors for output
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
yellow = Fore.YELLOW
bright = Style.BRIGHT
reset = Style.RESET_ALL

parser = argparse.ArgumentParser(description='This is a basic packet sniffer using scapy',usage='python3 main.py -i <interface>')
parser.add_argument('--interface','-i',help='Provide interface to capture packets',dest='Interface')
arg = parser.parse_args()

interface = arg.Interface

def packet_sniff(interface):
    if interface:
        sniff(iface = interface, prn = process_packets , store= False)
    else:
        sniff(prn= process_packets , store = False)


def process_packets(packet):
    if packet.haslayer(TCP):
        source_ip = packet[IP].src
        source_port = packet[TCP].sport
        destination_ip = packet[IP].dst
        destination_port = packet[TCP].dport

        print("{}{} [+] {} ip with port {} is making request at {} on port {}".format(bright,blue,source_ip,source_port,destination_ip,destination_port))


packet_sniff(interface)