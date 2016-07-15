import codecs
import copy
import datetime
import json
import os
import re
import shutil
import tempfile

import six

from mittn.fuzzer.archiver import Archiver
from mittn.fuzzer.pythonradamsa import PythonRadamsa
from mittn.fuzzer.anomalygenerator import AnomalyGenerator
from mittn.fuzzer.checker import Checker
from mittn.fuzzer.client import Client

class MittnFuzzer(object):

    def __init__(self, db_url=None, radamsa_path='/usr/bin/radamsa',
                 archiver=None, radamsa=None, generator=None, checker=None, client=None):
        self.archiver = archiver or Archiver(db_url)
        radamsa = radamsa or PythonRadamsa(radamsa_path)
        self.generator = generator or AnomalyGenerator(radamsa)
        self.checker = checker or Checker()
        self.client = client or Client()

        self.archiver.init()
