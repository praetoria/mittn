import socket
import codecs

from requests import Request
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
        req = Request(
            method  = method,
            headers = self.headers)

        if target.submission_type == 'urlparams':
            payload = dict_to_urlparams(payload)
            req.url = target.uri + payload

        elif target.submission_type == 'json':
            payload  = serialise_to_json(payload, True)
            req.url  = target.uri
            req.data = payload

        elif target.submission_type == 'urlencode':
            payload = serialise_to_url(payload)
            req.url  = target.uri
            req.data = payload
        else:
            raise NotImplemented
        resp = self.send(
            request = req.prepare(),
            timeout = self.timeout)
        return resp
"""
        try:
            resp = self.send(
                request = req.prepare(),
                timeout = 30)
        except RequestException as e:
            return e
"""
