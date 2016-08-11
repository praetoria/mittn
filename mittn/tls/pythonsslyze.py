import subprocess
from tempfile import NamedTemporaryFile
import xml.etree.ElementTree as ET
import os

class PythonSslyze(object):
    def __init__(self,path):
        self.path = path
        # check that sslyze is the correct version
        try:
            output = subprocess.check_output([path, "--version"])
            if b"0.13" not in output:
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


