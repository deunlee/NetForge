import os
from typing import Type
import scapy.all as scapy
from scapy.all import get_working_if, ltoa, conf
from scapy.interfaces import NetworkInterface

from src.utils import *


class NetForge_Interface:
    def __init__(self, interface: NetworkInterface | None = None):
        self.interface = interface # selected interface


    def get_selected_interface(self) -> NetworkInterface | None:
        return self.interface


    #========================= UTILS =========================#


    def get_gateway_address(self, interface: NetworkInterface) -> str | None: # (ex: '192.168.0.1')
        routes = get_unicast_routes()
        for route in routes:
            if route[2] == '0.0.0.0':
                continue # Skip connected route
            if route[3] == interface.network_name:
                return route[2]
        return None


    def get_gateway_address_of_selected_interface(self) -> str | None:
        return self.get_gateway_address(self.select_interface)


    #========================= MENUS =========================#

    def show_forwarding_status(self) -> None:
        if is_windows():
            print('[*] Retrieving forwarding status of all interfaces...')

            run_powershell('''Get-NetIPInterface
                | Where-Object {$_.AddressFamily -eq 'IPv4'}
                | select ifIndex,InterfaceAlias,InterfaceMetric,ConnectionState,Forwarding
                | Sort-Object -Property
                    @{Expression = 'ConnectionState'; Descending = $true},
                    @{Expression = 'InterfaceAlias'; Descending = $false}
                | Format-Table''')
        elif is_linux():
            print('[-] Currently Linux is not supported.')
        elif is_macos():
            print('[-] Currently MacOS is not supported.')


    def set_forwarding_status(self, interface_index: int, status: bool) -> bool:
        if is_windows():
            ok = run_powershell(f'''Set-NetIPInterface 
                -InterfaceIndex {interface_index}
                -Forwarding {"Enabled" if status else "Disabled"}''')
        elif is_linux():
            # echo 1 > /proc/sys/net/ipv4/ip_forward
            # sysctl -w net.ipv4.ip_forward=1
            # vi /etc/sysctl.conf  -->  net.ipv4.ip_forward=1  (permanent)
            print('[-] Currently Linux is not supported.')
            return False
        elif is_macos():
            print('[-] Currently MacOS is not supported.')
            return False
        else:
            print('[-] Unknown operating system. Cannot change forwarding status.')
            return False

        if ok:
            print(f'[+] Successfully changed forwarding status to {"ENABLED" if status else "DISABLED"}.')
            return True
        print('[-] Failed to change forwarding status.')
        print('[-] Please retry with root or administrator privilege.')
        return False


    def select_interface(self): # NetworkInterface | None
        # powershell -command "Get-NetAdapter"
        selected_interface = None
        
        def get_network_interfaces():
            data   = scapy.conf.ifaces.data # NetworkInterfaceDict
            result = []
            for id in data:
                device = data[id]
                if device.is_valid() and device.mac != '':
                    result.append(device)
            return result

        print('[*] List of interfaces :')
        print()
        
        interfaces        = sorted(get_network_interfaces(), key=lambda x: x.description)
        default_interface = get_working_if() # NetworkInterface
        default_index     = default_interface.index if default_interface else 0
        routes            = get_unicast_routes()

        print('{:^5}  {:42}  {:17}  {:15}  {}'.format('Index', 'Interface', 'MAC', 'IPv4', 'Gateway'))
        print('=' * 110)
        for interface in interfaces:
            desc    = str_fixed_len(interface.description, 42)
            gateway = list(map(lambda x: 'Connected' if x[2] == '0.0.0.0' else x[2], 
                        filter(lambda x: x[3] == interface.network_name, routes)))
            print('{:>4}   {:42}  {:17}  {:15}  {}'.format(
                interface.index, desc, interface.mac, interface.ip,
                ', '.join(gateway) + (' (DEFAULT)' if interface.index == default_index else '')
            ))
        print('=' * 110)
        print()
        
        while True:
            try:
                idx = input(f'[?] Please enter the interface number to use ({default_index}) : ').strip()
            except KeyboardInterrupt:
                print()
                return None

            if idx == '': idx = str(default_index)
            if not idx.isdigit():
                print('\n[-] Please enter a number.\n')
                return None
            try:
                selected_interface = conf.ifaces.dev_from_index(int(idx))
                break
            except:
                print('\n[-] Please check the interface number.\n')

        print()
        print(f'[+] The selected interface is "{selected_interface.description}".\n')
        
        flags = str(interface.flags).replace('+', ', ')
        print(f'[+] NetName : {selected_interface.network_name}')
        print(f'[+] Flags   : {flags}\n')
        
        return selected_interface

