import random
from collections import namedtuple
from urllib.parse import urlparse

USER_AGENT_LIST = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.48',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
]


def get_random_user_agent() -> str:
    return random.choice(USER_AGENT_LIST)


def parse_url(url: str):
    if not url.startswith(('http://', 'https://', '//')):
        url = 'http://' + url
    default_port = 443 if url.startswith('https://') else 80
    info = urlparse(url)
    ParsedURL = namedtuple('ParsedURL', ['host', 'path', 'port'])
    return ParsedURL(
        info.netloc,
        info.path if info.path != '' else '/',
        info.port if info.port else default_port
    )


def make_http_header(url: str, method: str = 'GET', complete_header: bool = True, length: int | None = None) -> str:
    url_info = parse_url(url)
    headers = [
        f'{method.upper()} {url_info.path} HTTP/1.1',
        f'Host: {url_info.host}',
        'Accept-Language: en-GB,en;q=0.9,en-US;q=0.8',
        'Accept-Encoding: gzip, deflate, br',
        f'User-Agent: {get_random_user_agent()}'
    ]
    if length != None:
        headers.append(f'Content-Length: {length}')
    headers.append('')
    return '\r\n'.join(headers) + ('\r\n' if complete_header else '')

