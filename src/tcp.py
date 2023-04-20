import os, sys, time, itertools
import scapy.all as scapy
from scapy.interfaces import NetworkInterface

from .utils import *
from .interface import NF_Interface
from .ddos.cnc import NetForge_DDoS_CNC_Server

class NF_TCPUDPTool:
    def __init__(self, interface: NetworkInterface): 
        self.interface = interface

    #========================= MENUS =========================#

    def menu(self) -> None:
        def print_menu():
            print(f'''
 +-------------------------------------------------------------------+
 |                        < TCP/UDP Attack >                         |
 +-------------------------------------------------------------------+
 |                                                                   |
 |   (1) TCP Flooding                  (2) UDP Flooding              |
 |                                                                   |
 |   (3) DDoS Flooding (Run C&C Server)                              |
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
                print('TODO feature')
                continue
            elif i == '2':
                print('TODO feature')
                continue
            elif i == '3':
                ip = input('[?] Enter a IP address to DDoS attack : ').strip()
                print()
                if not is_valid_ipv4(ip):
                    print('[-] IP address entered is invalid.\n')
                    continue
                port = int((input('[?] Enter a port (UDP) (8080) : ') or '8080').strip())
                threads = int((input('[?] Enter thread count to use (10) : ') or '10').strip())
                cnc = NetForge_DDoS_CNC_Server(ip, port, threads)
                cnc.start()
                break
            else:
                continue

            try:
                input('[?] Press enter key to back to menu. ')
            except KeyboardInterrupt:
                print()
            print_menu()

