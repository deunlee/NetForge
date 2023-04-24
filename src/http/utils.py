import random
from collections import namedtuple
from urllib.parse import urlparse


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


################################################################################


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


################################################################################


HTTP_CODE_TO_STR = {
    100: 'Continue',
    101: 'Switching Protocol',
    102: 'Processing', # WebDAV (deprecated)
    103: 'Early Hints', 

    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    203: 'Non-Authoritative Information',
    204: 'No Content',
    205: 'Reset Content',
    206: 'Partial Content',
    207: 'Multi-Status', # WebDAV
    208: 'Multi-Status', # WebDAV
    226: 'IM Used',      # HTTP Delta encoding

    300: 'Multiple Choice',
    301: 'Moved Permanently',
    302: 'Found',
    303: 'See Other',
    304: 'Not Modified',
    305: 'Use Proxy', # (deprecated)
    307: 'Temporary Redirect',
    308: 'Permanent Redirect',

    400: 'Bad Request',
    401: 'Unauthorized',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    407: 'Proxy Authentication Required',
    408: 'Request Timeout',
    409: 'Conflict',
    410: 'Gone',
    411: 'Length Required',
    412: 'Precondition Failed',
    413: 'Payload Too Large',
    414: 'URI Too Long',
    415: 'Unsupported Media Type',
    416: 'Requested Range Not Satisfiable',
    417: 'Expectation Failed',
    418: 'I\'m a teapot',

    421: 'Misdirected Request',
    422: 'Unprocessable Entity', # WebDAV
    423: 'Locked',               # WebDAV
    424: 'Failed Dependency',    # WebDAV
    426: 'Upgrade Required',
    428: 'Precondition Required',
    429: 'Too Many Requests',
    431: 'Request Header Fields Too Large',
    451: 'Unavailable For Legal Reasons',

    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported',
    506: 'Variant Also Negotiates',
    507: 'Insufficient Storage',
    508: 'Loop Detected',
    510: 'Not Extended',
    511: 'Network Authentication Required',
}

def http_code_to_str(code: int) -> str:
    if code in HTTP_CODE_TO_STR:
        return HTTP_CODE_TO_STR[code]
    return str(code)
