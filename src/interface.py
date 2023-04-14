import os
import scapy.all as scapy
from scapy.interfaces import NetworkInterface, NetworkInterfaceDict

from src.utils import *


class NF_Interface:
    def __init__(self, interface: NetworkInterface | None = None):
        self.interface = interface # selected interface


    def get_selected_interface(self) -> NetworkInterface | None:
        return self.interface

    #========================= UTILS =========================#

    @classmethod
    def get_valid_interfaces(cls) -> list[NetworkInterface]:
        data: NetworkInterfaceDict | None = scapy.conf.ifaces.data
        result = []
        for interface_id in data:
            interface = data[interface_id]
            if interface.is_valid() and interface.mac != '':
                result.append(interface)
        return sorted(result, key=lambda x: x.description)


    @classmethod
    def get_unicast_routes(cls):
        data = scapy.conf.route.routes # [(Network: int, Netmask: int, Gateway: str, Iface: str, OutputIP: str, Metric: int)]
        result = []
        for route in data:
            netmask = scapy.ltoa(route[1])
            if netmask == '255.255.255.255' or netmask == '240.0.0.0':
                continue # Skip broadcast and multicast
            result.append(route)
        return result


    @classmethod
    def get_network_address_with_cidr(cls, interface: NetworkInterface) -> str | None: # (ex: '192.168.0.0/24')
        routes = cls.get_unicast_routes()
        routes = list(filter(lambda x: x[3] == interface.network_name and x[2] == '0.0.0.0', routes))
        # '0.0.0.0' for connected route
        if len(routes):
            return f'{scapy.ltoa(routes[0][0])}/{bin(routes[0][1]).count("1")}'
        return None


    @classmethod
    def get_gateway_address(cls, interface: NetworkInterface) -> str | None: # (ex: '192.168.0.1')
        routes = cls.get_unicast_routes()
        for route in routes:
            if route[2] == '0.0.0.0':
                continue # Skip connected route
            if route[3] == interface.network_name:
                return route[2]
        return None


    def get_gateway_address_of_selected_interface(self) -> str | None:
        return self.get_gateway_address(self.select_interface)

    #========================= MENUS =========================#

    def menu(self) -> None:
        def print_menu():
            selected = self.interface.description if self.interface else 'not selected'
            selected = str_fixed_len(selected, 52)
            info = ''
            if self.interface:
                network = self.get_network_address_with_cidr(self.interface)
                gateway = self.get_gateway_address(self.interface)
                info = '\n |   Network: {:18}      Gateway: {:15}       |'.format(
                    network if network else 'no network', gateway if gateway else 'no gateway'
                )
            print(f'''
 +-------------------------------------------------------------------+
 |                        < Interface Menu >                         |
 +-------------------------------------------------------------------+
 |   Interface: {selected} |{info}
 +-------------------------------------------------------------------+
 |                                                                   |
 |   (1) Select Interface             (2) Show Routing Table         |
 |                                                                   |
 |   (3) Show Forwarding Status                                      |
 |   (4) Enable Packet Forwarding     (5) Disable Packet Forwarding  |
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
                self.select_interface()
            elif i == '2':
                print(scapy.conf.route)
                print()
            elif i == '3':
                self.show_forwarding_status()
            elif i == '4':
                if not self.interface:
                    print('[-] Please select an interface first.\n')
                else:
                    self.set_forwarding_status(True, self.interface)
                    print()
            elif i == '5':
                self.set_forwarding_status(False)
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


    def show_forwarding_status(self) -> None:
        if is_windows():
            print('[*] Retrieving forwarding status of all interfaces...')

            run_powershell('''Get-NetIPInterface
                | Where-Object {$_.AddressFamily -eq 'IPv4'}
                | select ifIndex,InterfaceAlias,InterfaceMetric,ConnectionState,Forwarding
                | Sort-Object -Property
                    @{Expression = 'ConnectionState'; Descending = $true},
                    @{Expression = 'InterfaceAlias'; Descending = $false}
                | Format-Table''', hide_output=False)
        elif is_linux():
            os.system('cat /proc/sys/net/ipv4/ip_forward')
            os.system('sysctl -a | grep net.ipv4.ip_forward')

            print('[-] Currently Linux is not supported.')
        elif is_macos():
            print('[-] Currently MacOS is not supported.')


    def set_forwarding_status(self, status: bool, interface: NetworkInterface | None = None) -> bool:
        if is_windows():
            if interface == None:
                ok = run_powershell(f'''Set-NetIPInterface -Forwarding {"Enabled" if status else "Disabled"}''')
            else:
                ok = run_powershell(f'''Set-NetIPInterface 
                    -InterfaceIndex {interface.index}
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


    def select_interface(self) -> None:
        # powershell -command "Get-NetAdapter"
        # powershell -command "Get-NetIPInterface"
        print('[*] List of network interfaces : \n')
        
        interfaces        = self.get_valid_interfaces()
        default_interface = scapy.get_working_if() # NetworkInterface
        default_index     = default_interface.index if default_interface else 0
        routes            = self.get_unicast_routes()

        print('{:^5}  {:42}  {:17}  {:15}  {}'.format('Index', 'Interface', 'MAC', 'IPv4', 'Gateway'))
        print('=' * 110)
        for interface in interfaces:
            desc    = str_fixed_len(interface.description, 42)
            gateway = list(map(lambda x: 'Connected' if x[2] == '0.0.0.0' else x[2], 
                        filter(lambda x: x[3] == interface.network_name, routes)))
            print('{:>4}   {:42}  {:17}  {:15}  {}'.format(
                interface.index, desc, interface.mac, interface.ip, ', '.join(gateway)
            ))
        print('=' * 110)
        print()
        
        while True:
            try:
                index = input(f'[?] Please enter the interface number to use ({default_index}) : ').strip()
            except KeyboardInterrupt:
                print()
                self.interface = None
                return
            if index == '': index = str(default_index)
            if not index.isdigit():
                print('\n[-] Please enter a number.\n')
                continue
            try:
                self.interface = scapy.conf.ifaces.dev_from_index(int(index))
                break
            except:
                print('\n[-] Please check the interface number.\n')

        print()
        print(f'[+] Interface : {self.interface.description}')
        print(f'[+] Alias     : {self.interface.name}')
        print(f'[+] Net Name  : {self.interface.network_name}')
        print(f'[+] Flags     : {str(interface.flags).replace("+", ", ")}\n')


