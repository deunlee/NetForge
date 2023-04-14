import os, sys, platform, time, itertools, re
import scapy.all as scapy
from scapy.all import get_working_if, ltoa, conf

def run_powershell(command: str) -> bool:
    return_code = os.system(f'powershell -command "{command}"'.replace('\n', ' '))
    return True if return_code == 0 else False

def is_windows() -> bool:
    return platform.system() == 'Windows'

def is_linux() -> bool:
    return platform.system() == 'Linux'

def is_macos() -> bool:
    return platform.system() == 'Darwin'


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




def get_network_addr_with_cidr(interface): # NetworkInterface -> str | None (ex: Iface -> '192.168.0.0/24')
    routes = filter(lambda x: x[3] == interface.network_name, get_unicast_routes())
    try:
        route = next(filter(lambda x: x[2] == '0.0.0.0', routes)) # Connected route
    except:
        return None
    return f'{ltoa(route[0])}/{bin(route[1]).count("1")}'

