import codecs
import copy
import datetime
import json
import os
import re

import six

from mittn.archiver import Archiver
from mittn.fuzzer.pythonradamsa import PythonRadamsa
from mittn.fuzzer.anomalygenerator import AnomalyGenerator
from mittn.fuzzer.checker import Checker
from mittn.fuzzer.client import Client
from mittn.fuzzer.target import Target
from mittn.config import Config
from mittn.fuzzer.issue import Issue

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
        self.checker = checker or Checker()
        if self.config.allowed_statuses:
            self.config.allowed_statuses = [int(i) for i in self.config.allowed_statuses]
        if self.config.disallowed_statuses:
            self.config.disallowed_statuses = [int(i) for i in self.config.disallowed_statuses]
        self.checker.allowed_status_codes = self.config.allowed_statuses
        self.checker.disallowed_status_codes = self.config.disallowed_statuses

        self.client = client or Client()
        self.client.timeout = int(self.config.timeout)

        self.targets = []

    def init(self):
        #create and test database connection
        self.archiver.init()
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
            responses = []
            for payload in self.generator.generate_anomalies(target.valid_submission,
                    [target.valid_submission],
                    int(self.config.anomalies)):
                for method in methods:
                    responses.append( self.client.do_target(target, method, payload))
            for response in responses:
                if self.checker.check(response, None):
                    newissue = Issue.from_resp_or_exc(target.scenario_id, response)
                    if not self.archiver.known_false_positive(newissue):
                        self.archiver.add_issue(newissue)
