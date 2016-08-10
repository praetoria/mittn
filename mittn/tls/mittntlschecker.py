# pylint: disable=E0602,E0102

"""
Copyright (c) 2013-2014 F-Secure
See LICENSE for details
"""

from ..config import Config
from .pythonsslyze import PythonSslyze
from .tlschecker import TlsChecker

# TODO: either remove this class or use MittnTlsChecker with this
class Target(object):
    """ Contains hostname, portnumber and a dict
        of protocols that should be enabled/disabled. """

    def __init__(self,host,port):
        self.host = host
        self.port = port

class MittnTlsChecker(object):
    """ This is the actual tlschecker object.
        It by default loads configuration from mittn.conf.
        
        Configuration can be changed by providing a different
        Config object.
        Additional checks can be implemented by providing a
        customized Checker object or a subclassed instance."""

    def __init__(self,sslyze_path=None,
            config=None, checker=None):
        # Config uses defaults
        # unless it finds settings in the provided file
        self.config = config or Config('tlschecker')
        self.sslyze = PythonSslyze(self.config.sslyze_path)

        # checker checks for misconfigurations
        # by analyzing the xml produced by PythonSslyze
        self.checker = checker or TlsChecker(config)

    def run(self,host,port=443):
        target = Target(host,port)
        protos_e = self.config.protocols_enabled
        protos_d = self.config.protocols_disabled

        xmloutputs = self.sslyze.run(target,protos_e + protos_d)

        # perform checks on the output from sslyze
        return self.checker.run(xmloutputs)
