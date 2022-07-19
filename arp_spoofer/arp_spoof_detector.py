#!/usr/bin/ven python

import argparse
import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        print(packet.show())


parser = argparse.ArgumentParser(description="ARP Spoof Detector - linux")
parser.add_argument('-i', '--interface', dest='interface', help='Network interface to use')

sniff(parser.parse_args().interface)