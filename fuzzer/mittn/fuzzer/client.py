import socket

from requests.exceptions import Timeout, RequestException
from requests.models import Response
from requests.sessions import Session

FQDN = socket.getfqdn()
HOSTNAME = socket.gethostbyname(socket.gethostname())

class Client(Session):

    def __init__(self):
        super(Client, self).__init__()
        self.headers.update({
            'Cache-Control': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (compatible; Mittn HTTP Fuzzer-Injector)',
            #'X-Abuse': 'This is an automatically generated robustness test request from %s [%s]' % (FQDN, HOSTNAME),
            'Connection': 'close',
            'X-Valid-Case-Instrumentation': 'This is a valid request that should succeed',
        })

    def request_safe(self, *args, **kwargs):
        try:
            resp = self.request(*args, **kwargs)
        except RequestException as e:
            return e
        return resp
