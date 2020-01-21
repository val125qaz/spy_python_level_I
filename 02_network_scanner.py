#!/usr/bin/env python
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target" , help="Target IP /IP range.")
    (options, arguments) = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(results_list):
    i = 0
    array = []
    array2 = []

    print("IP\t\t\tMAC Address\n-----------------------------")
    for client in results_list:
        array.append(client["ip"])
        array.append(client["mac"])

        array2.append(array)
        array = []
        #print(array2)
    for x in array2:

        print "[" + str(i) + "]  " + x[0]+" \t\t  " + x[1]
        i += 1

    target = input("Select your target ? ")
    print(array2[target][0] +"  "+ array2[target][1])


options = get_arguments()
scan_result = scan(options.target)

try:
    print_result(scan_result)
except :
    print("[+] Wrong Target Try again .........\n")
