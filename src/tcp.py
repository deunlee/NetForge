
import os, sys, time, itertools
import scapy.all as scapy
from scapy.interfaces import NetworkInterface

from .utils import *
from .interface import NF_Interface


class NF_TCPUDPTool:
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
 |                        < TCP/UDP Attack >                         |
 +-------------------------------------------------------------------+
 |   Interface: {selected} |{info}
 +-------------------------------------------------------------------+
 |                                                                   |
 |   No menu yet.                                                    |
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
            else:
                continue

            try:
                input('[?] Press enter key to back to menu. ')
            except KeyboardInterrupt:
                print()
            print_menu()

