import codecs
import copy
import datetime
import json
import os
import re

import six

from mittn.fuzzer.archiver import Archiver
from mittn.fuzzer.pythonradamsa import PythonRadamsa
from mittn.fuzzer.anomalygenerator import AnomalyGenerator
from mittn.fuzzer.checker import Checker
from mittn.fuzzer.client import Client
from mittn.fuzzer.target import Target
from mittn.fuzzer.config import Config
from mittn.fuzzer.issue import Issue

class MittnFuzzer(object):

    def __init__(self, archiver=None, radamsa=None, generator=None,
            checker=None, client=None,config=None):
        self.config = config or Config("mittn.conf","fuzzer")
        self.archiver = archiver or Archiver(self.config.db_url)
        radamsa = radamsa or PythonRadamsa(self.config.radamsa_path)
        self.generator = generator or AnomalyGenerator(radamsa)
        self.checker = checker or Checker()
        self.client = client or Client()

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
            for payload in self.generator.generate_anomalies(target.valid_submission, [target.valid_submission], 1):
                for method in methods:
                    responses.append( self.client.do_target(target, method, payload))
            for response in responses:
                if self.checker.check(response, None, [500]):
                    newissue = Issue.from_resp_or_exc(target.scenario_id, response)
                    if not self.archiver.known_false_positive(newissue):
                        self.archiver.add_issue(newissue)
