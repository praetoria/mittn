from mittn.fuzzer.utils import urlparams_to_dict
from urllib import parse
import json

class Target():
    
    def __init__(self, scenario_id, method, uri, submission_type, valid_submission):
        self.scenario_id      = scenario_id       #a unique identifier for this target/testable endpoint
        self.method           = method            #probably a POST or a GET
        self.uri              = uri               #the URI, obviously important
        self.submission_type  = submission_type   #the typs as which the valid submission should be interpreted (urlencode, json, url-parameters
        self.valid_submission = {}
        if self.submission_type == 'urlparams':
            self.valid_submission = urlparams_to_dict(valid_submission)

        elif self.submission_type == 'json':
            self.valid_submission = json.loads(valid_submission)

        elif self.submission_type == 'urlencode':
            self.valid_submission = parse.parse_qs(valid_submission)
