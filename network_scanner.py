#!/usr/bin/env python

import scapy.all as scapy
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-t",
                  "--target",
                  dest="ip_range",
                  help="IP range of network in which to search for devices")
(options) = parser.parse_args()

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip":element[1].psrc, "MAC":element[1].psrc}
        clients_list.append(client_dict)
    return clients_list
def print_result(results_list):
    print("IP\t\t\t\tMAC Address\n-------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t\t" + client["MAC"])

# scan_result = scan("192.168.59.1/24")
scan_result = scan(options.ip_range)
print_result(scan_result)
