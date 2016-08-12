from mittn.archiver import Archiver
from mittn.fuzzer.pythonradamsa import PythonRadamsa
from mittn.fuzzer.anomalygenerator import AnomalyGenerator
from mittn.fuzzer.checker import Checker
from mittn.fuzzer.client import Client
from mittn.fuzzer.target import Target
from mittn.config import Config
from mittn.fuzzer.fuzzerissue import FuzzerIssue

class MittnFuzzer(object):

    def __init__(self, archiver=None, radamsa=None, generator=None,
            checker=None, client=None,config=None):
        self.config = config or Config("fuzzer","mittn.conf")
        db_url = None
        if hasattr(self.config,'db_url'):
            db_url = self.config.db_url
        self.archiver = archiver or Archiver(db_url)
        radamsa = radamsa or PythonRadamsa(self.config.radamsa_path)
        self.generator = generator or AnomalyGenerator(radamsa)
        self.checker = checker or Checker(
			self.config.allowed_status_codes,
			self.config.disallowed_status_codes)
        self.client = client or Client()
        self.client.timeout = int(self.config.timeout)

        self.targets = []

    def init(self):
        #create and test database connection
        self.archiver.init(FuzzerIssue)
        #configure how issues are created
        pass

    def add_target(self, target):
        #add a target object that mittn will be ran against
        self.targets.append(target)
        pass

    def fuzz(self):
        methods = self.config.methods
        #fuzz and inject all the added targets
        for target in self.targets:
			#TODO: authentication or re-authentication should be done before thesting the valid target.
            resp = self.client.do_target(target, target.method, target.valid_submission);
            if self.checker.check(resp, self.config.body_errors):
                #the request either returned a bad code or an exception occured.
                #since this is testing a vlid case, this should not happen, fail
                #the test run and print some diagnostics.
                raise Exception("The valid case for %s failed, check that the target is up and reachable." % (target.scenario_id))
            responses = []
            for payload in self.generator.generate_anomalies(target.valid_submission,
                    [target.valid_submission],
                    int(self.config.anomalies)):
				#TODO: here valic case instrumentation should be done
                for method in methods:
                    responses.append( self.client.do_target(target, method, payload))
			#TODO: inject with static anomalies here. The current AnomalyGenerator is broken.
            for response in responses:
                if self.checker.check(response, self.config.body_errors):
                    newissue = FuzzerIssue.from_resp_or_exc(target.scenario_id, response)
                    self.archiver.add_if_not_found(newissue)
