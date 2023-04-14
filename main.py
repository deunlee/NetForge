import os, sys

NETFORGE_VERSION = '1.0.0'

print("  _   _      _   _____                     ")
print(" | \ | | ___| |_|  ___|__  _ __ __ _  ___  ")
print(" |  \| |/ _ \ __| |_ / _ \| '__/ _` |/ _ \ ")
print(" | |\  |  __/ |_|  _| (_) | | | (_| |  __/ ")
print(" |_| \_|\___|\__|_|  \___/|_|  \__, |\___|  (V." + NETFORGE_VERSION + ")")
print("                               |___/       ")

if sys.version_info < (3, 10):
    print('[-] Python 3.10 or higher is required. Current version is ' + 
        str(sys.version_info[0]) + '.' + str(sys.version_info[1]) + '.' + str(sys.version_info[2]) + '.')
    sys.exit(1)

try:
    import scapy.all as scapy
except ModuleNotFoundError:
    print('[-] Some libraries are not installed.')
    print('[-] Please install them with the following command.\n')
    print('[*] pip install -r requirements.txt\n')
    sys.exit()


from src.utils import *
from src.interface import NF_Interface
from src.arp       import NF_ARPTool
from src.dns       import NF_DNSTool


def main():
    nf_interface = NF_Interface()

    def print_menu():
        print(f'''
 +-------------------------------------------------------------------+
 |                           < Main Menu >                           |
 +-------------------------------------------------------------------+
 |                                                                   |
 |   (1) Select Interface             (2) Interface Menu             |
 |                                                                   |
 |   (3) ARP Tools                    (4) DNS Tools                  |
 |                                                                   |
 |   (0) Exit                                                        |
 |                                                                   |
 +-------------------------------------------------------------------+\n''')

    print_menu()
    while True:
        try:
            i = input('[?] Enter menu number : ')
        except KeyboardInterrupt:
            print('\n[*] Exit...\n')
            break
        print()

        if i == '1':
            nf_interface.select_interface()
        elif i == '2':
            nf_interface.menu()
        elif i == '3':
            if not nf_interface.get_selected_interface():
                print('[-] Please select an interface first.')
            else:
                nf_arp_tool = NF_ARPTool(nf_interface.get_selected_interface())
                nf_arp_tool.menu()
        elif i == '4':
            if not nf_interface.get_selected_interface():
                print('[-] Please select an interface first.')
            else:
                nf_dns_tool = NF_DNSTool(nf_interface.get_selected_interface())
                nf_dns_tool.menu()
        elif i == '0':
            print('[*] Exit...\n')
            break
        else:
            print('[-] Please select the menu again.')

        print_menu()


if __name__ == '__main__':
    main()
