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
        methods = ['GET','POST'] #this would really come from the configuration file!
        #fuzz and inject all the added targets
        for target in self.targets:
            for payload in self.generator.generate_anomalies(target.valid_submission, [target.valid_submission], 1):
                for method in methods:
                    self.client.do_target(target, method, payload)
