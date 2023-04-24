import sys, asyncio, aiohttp, random

if __name__ == '__main__':
    sys.path.append('./')
    from src.http.utils import http_code_to_str
else:
    from .utils import http_code_to_str


status_http = {}
status_err = {
    'ConnErr': 0, 
    'ConnRefused': 0,
    'ServerDisconn': 0,
    'TimeOut': 0,
    'OSError': 0,
    'UnknownErr': 0,
}


async def main(url, timeout=300):
    global status_http, status_err
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout) as res:
                if res.status in status_http:
                    status_http[res.status] += 1
                else:
                    status_http[res.status] = 1

                print(res.status)

    except asyncio.TimeoutError:
        status_err['TimeOut'] += 1

    except aiohttp.ClientConnectorError as e:
        # TCP 연결 불가 오류 (`aiohttp.connector.TCPConnector`에서 발생)

        # 1. 서버에서 명시적으로 연결을 거부한 경우
        # (포트가 열리지 않은 경우: 3-way handshake 실패, SYN -> RST/ACK)
        if sys.platform == 'win32' and e.os_error.winerror == 1225:
            # `The remote computer refused the network connection` (`원격 컴퓨터가 네트워크 연결을 거부했습니다`)
            status_err['ConnRefused'] += 1
            return
        elif sys.platform == 'linux' and e.errno == 111:
            # `Connect call failed`
            status_err['ConnRefused'] += 1
            return

        # 2. 기타
        status_err['ConnErr'] += 1
        if sys.platform == 'win32':
            print(f'ClientConnectorError({e.os_error.winerror}): {str(e)}')
        else:
            print(f'ClientConnectorError({e.errno}): {str(e)}')

    except aiohttp.ServerDisconnectedError:
        # TCP 연결 수립 후, 서버에서 강제로 연결을 끊은 경우 (3-way handshake 성공, RST)
        status_err['ServerDisconn'] += 1

    except aiohttp.ClientOSError as e:
        # 운영체제 오류

        # 1. TCP 연결 수립 후, 서버에서 강제로 연결을 끊은 경우 (3-way handshake 성공, RST/ACK)
        # (ServerDisconnectedError와 비슷하지만 ACK 플래그가 있음)
        if sys.platform == 'win32' and e.winerror == 64:
            # `The specified network name is no longer available` (`지정된 네트워크 이름을 더 이상 사용할 수 없습니다`)
            status_err['ServerDisconn'] += 1
            return
        elif sys.platform == 'linux' and e.errno == 104:
            # `Connection reset by peer`
            status_err['ServerDisconn'] += 1
            return
        
        # 2. Semaphore Timeout
        if sys.platform == 'win32' and e.winerror == 121:
            # `The semaphore timeout period has expired` (`세마포 제한 시간이 만료되었습니다`)
            status_err['OSError'] += 1
            print('Semaphore Timeout')
            return

        # 3. 기타
        status_err['OSError'] += 1
        if sys.platform == 'win32':
            print(f'OSError({e.winerror}): {e.strerror}')
        else:
            print(f'OSError({e.errno}): {e.strerror}')

    except Exception as e:
        status_err['UnknownErr'] += 1
        print('UnknownError', e)


url = input('Enter url to start: ').strip()

print('Start')
loop = asyncio.get_event_loop()
print(loop)
print(type(loop))

try:
    loop.run_until_complete(
        asyncio.gather(*(main(url) for i in range(2000)))
    )
except ValueError as e:
    # too many file descriptors in select()
    print('ValueError!!!', e)
except Exception as e:
    print('실행 불가', e)

print('END\n\n\n')



for key in status_http:
    count = status_http[key]
    if count == 0: continue
    print(f'HTTP {key} ({http_code_to_str(key)}) ==> {count} times')

for key in status_err:
    count = status_err[key]
    if count == 0: continue
    print(f'{key}: {count}')

