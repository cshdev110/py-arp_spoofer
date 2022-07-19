#!/usr/bin/ven python

import argparse
import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # with this function, scapy.srp() we send packets and receive the answer
    # [0] is set as we need just the first list only.
    #  With verbose=false the top of the information is not printed out
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc  # Retrieving the mac-address of the ip given


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            ip_spoofer = packet[scapy.ARP].psrc
            real_mac = get_mac(ip_spoofer)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("[+] Alert of ARP Spoof on network, coming from IP: " + ip_spoofer)
        except IndexError:
            pass


parser = argparse.ArgumentParser(description="ARP Spoof Detector - linux")
parser.add_argument('-i', '--interface', dest='interface', help='Network interface to use')

sniff(parser.parse_args().interface)