#importing all required modules

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
magenta = Fore.MAGENTA
bright = Style.BRIGHT
reset = Style.RESET_ALL

#code for taking arguments
parser = argparse.ArgumentParser(description='This is a basic packet sniffer using scapy',usage='python3 main.py -i <interface>')
parser.add_argument('--interface','-i',help='Provide interface to capture packets',dest='Interface')
arg = parser.parse_args()


interface = arg.Interface

#sniffing packet using sniff()
def packet_sniff(interface):
    if interface:
        sniff(iface = interface, prn = process_packets , store= False)
    else:
        sniff(prn= process_packets , store = False)

#method for defining processes on packet
def process_packets(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        source_ip = packet[IP].src
        source_port = packet[TCP].sport
        destination_ip = packet[IP].dst
        destination_port = packet[TCP].dport

        print("{}{} [+] {} ip with port {} is making request at {} on port {} {}".format(bright,blue,source_ip,source_port,destination_ip,destination_port,reset))

    if packet.haslayer(HTTPRequest) and packet.haslayer(IP):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method_used = packet[HTTPRequest].Method.decode()
        print(f'{bright}{green} {source_ip} is making http_request at {url} using {method_used} method {reset}')
        print('{} HTTP data :-'.format(bright))
        print(packet[HTTPRequest].show())
        if packet.haslayer(Raw):
            print(f"{red}Sniffer finds Something usefull : {packet.getlayer(Raw).load.decode()}{reset}")


#exception handling
try:
    packet_sniff(interface)

except KeyboardInterrupt:
    print(f'{bright}{yellow} Program Ended Successfully')
except :
    print(f'{bright}{red} Program ended Unconditionally with exit code -1')
    
