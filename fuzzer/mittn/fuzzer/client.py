import socket
import codecs

from requests.exceptions import Timeout, RequestException
from requests.models import Response
from requests.sessions import Session

from mittn.fuzzer.utils import *


FQDN = socket.getfqdn()
HOSTNAME = socket.gethostbyname(socket.gethostname())



class Client(Session):

    def __init__(self):
        #XXX here we are overriding the 'strict' error handler with the
        #'ignore' handler of the codecs module. This will make utf-8
        #conversion succeed by removing invalid characters from the 
        #fuzzed data.
        #https://docs.python.org/3.4/library/stdtypes.html#bytes.decode
        codecs.register_error('strict', lambda err:('', err.start+1))

        super(Client, self).__init__()
        self.headers.update({
            'Cache-Control': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (compatible; Mittn HTTP Fuzzer-Injector)',
            #'X-Abuse': 'This is an automatically generated robustness test request from %s [%s]' % (FQDN, HOSTNAME),
            'Connection': 'close'
            #'X-Valid-Case-Instrumentation': 'This is a valid request that should succeed',
        })

    def do_target(self, target, method, payload):
        if target.submission_type == 'urlparams':
            payload = dict_to_urlparams(payload)
            self.request(
                url     = target.uri + payload,
                method  = method,
                verify  = False,
                timeout = self.timeout)
        elif target.submission_type == 'json':
            raise NotImplemented
        elif target.submission_type == 'urlencode':
            payload = serialise_to_url(payload)
            self.request(
                url     = target.uri,
                method  = method,
                data    = payload,
                verify  = False,
                timeout = self.timeout)
        else:
            raise NotImplemented

    def request_safe(self, *args, **kwargs):
        try:
            resp = self.request(*args, **kwargs)
        except RequestException as e:
            return e
        return resp
