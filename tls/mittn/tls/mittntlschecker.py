# pylint: disable=E0602,E0102

"""
Copyright (c) 2013-2014 F-Secure
See LICENSE for details
"""

import subprocess
from tempfile import NamedTemporaryFile
import os
import xml.etree.ElementTree as ET

from .config import Config
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

    def run(self,target):
        target.xmloutputs = {}
        # run sslyze separately for different protocols
        for proto in target.enabled_protos + target.disabled_protos:
            target.xmloutputs[proto] = self.run_single(target,proto)

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
            #print(ET.dump(xml))
        except subprocess.CalledProcessError as e:
            raise ValueError("Couldn't execute sslyze: %s" % e)
        except ET.ParseError as e:
            raise ValueError("Error parsing xml output from sslyze: %s" % e)
        finally:
            os.unlink(xmloutfile.name)
        return xml


class Target(object):
    """ Contains hostname, portnumber and a dict
        of protocols that should be enabled/disabled.

        Instances of this class are also used for saving
        sslyze's results per tested protocol in an attribute
        named xmloutput[protocol]."""

    def __init__(self,host,port,enabled_protos,disabled_protos):
        self.host = host
        self.port = port
        # protocols that should be enabled or disabled
        self.enabled_protos = enabled_protos
        self.disabled_protos = disabled_protos

class MittnTlsChecker(object):
    """ This is the actual tlschecker object.
        It by default loads configuration from mittn.conf.
        
        Configuration can be changed by providing a different
        Config object.
        Additional checks can be implemented by providing a
        customized Checker object or a subclassed instance."""

    def __init__(self,config_path="./mittn.conf",sslyze_path=None,
            config=None, checker=None):
        # Config uses defaults
        # unless it finds settings in the provided file
        self.config = config or Config(config_path)
        self.sslyze = PythonSslyze(self.config.sslyze_path)

        # checker checks for misconfigurations
        # by analyzing the xml produced by PythonSslyze
        self.checker = checker or TlsChecker(config)
        self.checker.config = self.config

    def run(self,host,port=443):
        target = Target(host,port,
                self.config.protocols_enabled,self.config.protocols_disabled)

        # puts results into target.xmloutputs[proto] dict
        self.sslyze.run(target)

        # perform checks on the output from sslyze
        return self.checker.run(target)
