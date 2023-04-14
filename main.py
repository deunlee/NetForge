import os, sys

print("  _   _      _   _____                     ")
print(" | \ | | ___| |_|  ___|__  _ __ __ _  ___  ")
print(" |  \| |/ _ \ __| |_ / _ \| '__/ _` |/ _ \ ")
print(" | |\  |  __/ |_|  _| (_) | | | (_| |  __/ ")
print(" |_| \_|\___|\__|_|  \___/|_|  \__, |\___| ")
print("                               |___/       \n")

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


from src.arp import NF_ARP_Tool
from src.utils import *


def main():

    interface = None

    while True:
        print('''
==================================================
=                    < MENU >                    =
=   1. Select Interface   2. Show Routing Table  =
=   3. ARP Scan           4. ARP Spoofing        =
=                                                =
=   0. Exit                                      =
==================================================
        ''')

        try:
            menu = input('[?] Select Menu : ')
        except KeyboardInterrupt:
            print('\n[*] Exit...\n')
            break
        print()

        if menu == '1':
            interface = select_interface()
        elif menu == '2':
            print(scapy.conf.route)
        elif menu == '3':
            if not interface:
                print('[-] Please select an interface first.')
            else:
                ARPTool = NF_ARP_Tool(interface)
                ARPTool.arp_scan()
        elif menu == '4':
            if not interface:
                print('[-] Please select an interface first.')
            else:
                ARPTool = NF_ARP_Tool(interface)
                ARPTool.arp_spoof()
        elif menu == '0':
            print('[*] Exit...\n')
            break
        else:
            print('[-] Please select the menu again.')


if __name__ == '__main__':
    main()
