import os, sys, time, itertools, re
import scapy.all as scapy
from scapy.all import get_working_if, ltoa, conf


def str_fixed_len(text, length):
    if len(text) <= length:
        return text + (' ' * (length - len(text)))
    return text[:length-3] + '...'


def netmask_to_cidr(netmask): # str -> int (ex: '255.255.255.0' -> 24)
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])


def is_valid_ipv4(ip): # str
    return re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip)


def get_unicast_routes():
    data   = scapy.conf.route.routes # [('Network', 'Netmask', 'Gateway', 'Iface', 'Output IP', 'Metric')]
    result = []
    for route in data:
        netmask = ltoa(route[1])
        if netmask == '255.255.255.255' or netmask == '240.0.0.0':
            continue # Skip broadcast and multicast
        result.append(route)
    return result


def get_ipv4_gateway(interface): # NetworkInterface -> str(ip) | None (ex: Iface -> '192.168.0.1')
    routes = get_unicast_routes()
    for route in routes:
        if route[2] == '0.0.0.0':
            continue # Skip connected route
        if route[3] == interface.network_name:
            return route[2]
    return None


def get_network_addr_with_cidr(interface): # NetworkInterface -> str | None (ex: Iface -> '192.168.0.0/24')
    routes = filter(lambda x: x[3] == interface.network_name, get_unicast_routes())
    try:
        route = next(filter(lambda x: x[2] == '0.0.0.0', routes)) # Connected route
    except:
        return None
    return f'{ltoa(route[0])}/{bin(route[1]).count("1")}'


def select_interface():
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
    print('=' * 120)
    for interface in interfaces:
        desc    = str_fixed_len(interface.description, 42)
        gateway = list(map(lambda x: 'Connected' if x[2] == '0.0.0.0' else x[2], 
                    filter(lambda x: x[3] == interface.network_name, routes)))
        print('{:>4}   {:42}  {:17}  {:15}  {}'.format(
            interface.index, desc, interface.mac, interface.ip,
            ', '.join(gateway) + (' (DEFAULT)' if interface.index == default_index else '')
        ))
    print('=' * 120)
    print()
    
    while True:
        idx = input(f'[?] Please enter the interface number to use ({default_index}) : ').strip()
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

