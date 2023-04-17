import time, threading

class ThreadWorker:
    def __init__(self, thread_count):
        self.threads      = []
        self.thread_count = thread_count
        self.is_running   = False
        self.main_func    = self._default_main_func
        self.main_arg     = None
        self.worker_func  = None
        self.worker_args  = None

    def _is_any_thread_alive(self):
        return True in [t.is_alive() for t in self.threads]

    def _default_main_func(self):
        time.sleep(0.5)

    def set_main_thread(self, func, arg = None):
        self.main_func = func
        self.main_arg  = arg
    
    def set_worker_thread(self, func, args = None):
        self.worker_func = func
        self.worker_args = args


    def run(self) -> bool:
        if self.is_running: return False
        self.is_running = True

        print(f'[*] Creating {self.thread_count} threads...\n')
        for i in range(self.thread_count):
            self.threads.append(threading.Thread(target=self.worker_func, args=self.worker_args, daemon=True))

        for i in range(self.thread_count):
            self.threads[i].start()
    
        try:
            if self.main_arg == None:
                while self._is_any_thread_alive():
                    self.main_func()
            else:
                while self._is_any_thread_alive():
                    self.main_func(self.main_arg)
        except KeyboardInterrupt:
            print('\n[!] Ctrl+C pressed! Stopping...\n')

        self.threads = []
        self.is_running = False
        return True


    def stop(self) -> bool:
        if not self.is_running: return False
        # TODO
        return True


class ThreadCounter():
    def __init__(self):
        self.lock = threading.Lock()
        self.cnt_active = 0
        self.cnt_closed = 0
        self.cnt_error  = 0

    def reset(self):
        self.lock.acquire()
        self.cnt_active = 0
        self.cnt_closed = 0
        self.cnt_error  = 0
        self.lock.release()

    def count_active(self):
        self.lock.acquire()
        self.cnt_active += 1
        self.lock.release()

    def count_inactive(self):
        self.lock.acquire()
        self.cnt_active -= 1
        self.lock.release()

    def count_closed(self):
        self.lock.acquire()
        self.cnt_closed += 1
        self.lock.release()

    def count_error(self):
        self.lock.acquire()
        self.cnt_error += 1
        self.lock.release()

    def print(self):
        self.lock.acquire()
        print(f'Active={self.cnt_active}, Closed={self.cnt_closed}, Error={self.cnt_error}')
        self.lock.release()



class ThreadCounter2():
    def __init__(self, keys: list[str]):
        self.lock = threading.Lock()
        self.keys = keys
        self.cnt = {}
        for key in keys:
            self.cnt[key] = 0

    def count(self, key: str, value: int = 1):
        self.lock.acquire()
        self.cnt[key] += value
        self.lock.release()

    def print(self):
        self.lock.acquire()
        s = []
        for key in self.keys:
            print(f'{key}={self.cnt[key]}, ', end='')
        # print(', '.join(s))
        print()
        self.lock.release()
