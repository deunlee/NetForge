import os, sys, platform, time, itertools, re
import scapy.all as scapy
from scapy.all import conf

def run_powershell(command: str, hide_output: bool = True) -> bool:
    return_code = os.system(f'powershell -command "{command}" {"> nul" if hide_output else ""} 2> nul'.replace('\n', ' '))
    return True if return_code == 0 else False

def is_windows() -> bool:
    return platform.system() == 'Windows'

def is_linux() -> bool:
    return platform.system() == 'Linux'

def is_macos() -> bool:
    return platform.system() == 'Darwin'


def str_fixed_len(text: str, length: int) -> str:
    if len(text) <= length:
        return text + (' ' * (length - len(text)))
    return text[:length-3] + '...'


# def netmask_to_cidr(netmask): # str -> int (ex: '255.255.255.0' -> 24)
#     return sum([bin(int(x)).count('1') for x in netmask.split('.')])


def is_valid_ipv4(ip: str) -> bool:
    return re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip)
