class Target():
    
    def __init__(self, scenario_id, method, uri, submission_type, valid_submission):
        self.scenario_id      = scenario_id       #a unique identifier for this target/testable endpoint
        self.uri              = uri               #the URI, obviously important
        self.method           = method            #probably a POST or a GET
        self.valid_submission = valid_submission  #valid URL parameters, http form comtent of JSON
        self.submission_type  = submission_type   #the typs as which the valid submission should be interpreted (formdata, json, urlparams
