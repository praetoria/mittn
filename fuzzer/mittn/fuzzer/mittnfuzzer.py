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

class MittnFuzzer(object):

    def __init__(self, db_url=None, radamsa_path='/usr/bin/radamsa',
                 archiver=None, radamsa=None, generator=None, checker=None, client=None):
        self.archiver = archiver or Archiver(db_url)
        radamsa = radamsa or PythonRadamsa(radamsa_path)
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
        methods = ['GET'] #this would really come from the configuration file!
        #fuzz and inject all the added targets
        for target in self.targets:
            for method in methods:
                for payload in self.generator.generate_anomalies(target.valid_submission, [target.valid_submission], 10):
                    self.client.request(
                        url     = target.uri + str(payload, 'iso-8859-1'),
                        method  = method,
                        verify  = False,
                        timeout = 30
                    )
                    #send the submission and check the response
                    pass

            for submission in self.generator.generate_static():
                #send the submission and check the response
                pass

