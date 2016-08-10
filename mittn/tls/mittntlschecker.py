# pylint: disable=E0602,E0102

"""
Copyright (c) 2013-2014 F-Secure
See LICENSE for details
"""

import subprocess
from tempfile import NamedTemporaryFile
import os
import xml.etree.ElementTree as ET

from ..config import Config
from .tlschecker import TlsChecker

class PythonSslyze(object):
    def __init__(self,path):
        self.path = path
        # check that sslyze is the correct version
        try:
            output = subprocess.check_output([path, "--version"])
            if b"0.13.6" not in output:
                raise ValueError("Didn't find version 0.13.6 of sslyze in %s" % path)
        except (subprocess.CalledProcessError, OSError) as e:
            raise ValueError("Couldn't execute sslyze from %s: %s" % (path, e))

    def run(self,target,protocols):
        xmloutputs = {}
        # run sslyze separately for different protocols
        for proto in protocols:
            xmloutputs[proto] = self.run_single(target,proto)
        return xmloutputs

    def run_single(self,target,proto):
        # run sslyze against a host and return xml output
        # this could be done with the sslyze python library
        xmloutfile = NamedTemporaryFile(delete=False)
        # remove the lock on the temporary file
        xmloutfile.close()
        try:
            subprocess.check_output([self.path,"--%s" % proto.lower(),
                "--compression", "--reneg",
                "--heartbleed", "--xml_out=" + xmloutfile.name,
                "--certinfo_full", "--hsts",
                "--http_get", "--sni=%s" % target.host,
                "%s:%s" % (target.host, target.port)])
            xml = ET.parse(xmloutfile.name)
        except subprocess.CalledProcessError as e:
            raise ValueError("Couldn't execute sslyze: %s" % e)
        except ET.ParseError as e:
            raise ValueError("Error parsing xml output from sslyze: %s" % e)
        finally:
            os.unlink(xmloutfile.name)
        return xml


# TODO: either remove this class or initialize MittnTlsChecker with this
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
