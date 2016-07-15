# pylint: disable=E0602,E0102

"""
Copyright (c) 2013-2014 F-Secure
See LICENSE for details
"""

import subprocess
from tempfile import NamedTemporaryFile
import re
import os
import xml.etree.ElementTree as ET
# The following for calculating validity times from potentially
# locale specific timestamp strings
import dateutil.parser
import dateutil.relativedelta
import pytz
from datetime import datetime

from .config import Config

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
        for proto in target.protocols.keys():
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

class Checker(object):
    def __init__(self):
        # configuration is at self.config
        pass

    def run(self,target):
        # check that disabled protocols are disabled
        # and run checks for enabled protocol(s)
        for proto in target.protocols.keys():
            if target.protocols[proto]:
                self.run_checks(target,proto)
            else:
                self.proto_disabled(target.xmloutputs[proto],target)

    def run_checks(self,target,proto):
        if not self.config:
            raise ValueError("Missing configuration for Tlschecker")

        # get results of the sslyze run for this protocol
        self.xml = target.xmloutputs[proto]
        self.proto_enabled(target)
        self.check_cert_begin()
        self.check_cert_end(self.config.days_valid)
        self.compression_disabled()
        self.secure_reneg()
        # only check if the lists have something to check
        if len(self.config.suites_preferred):
            self.cipher_suites_preferred()
        if len(self.config.suites_disabled):
            self.cipher_suites_disabled()
        if len(self.config.suites_enabled):
            self.cipher_suites_enabled()
        self.strict_tls_headers()
        self.heartbleed()
        self.sha1()
        self.check_dh_group_size(self.config.dh_group_size)
        self.trusted_ca()
        self.matching_hostname()
        self.check_public_key_size(self.config.public_key_size)

    # make sure connection is successful
    def proto_enabled(self,target):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")

        # The connection target should have been resolved
        # The .//foo notation is an Xpath
        assert len(root.findall('.//invalidTargets')) == 1, \
            "Target system did not resolve or could not connect"
        for error in root.findall('.//errors'):
            # There should be no connection errors
            assert len(error) == 0, \
                "Errors found creating a connection to %s:%s" % (target.host, target.port)
        num_acceptedsuites = 0
        for acceptedsuites in root.findall('.//acceptedCipherSuites'):
            num_acceptedsuites += len(acceptedsuites)
        # If there are more than zero accepted suites (for any enabled protocol)
        # the connection was successful
        assert num_acceptedsuites > 0, \
            "No acceptable cipher suites found at %s:%s" % (target.host, target.port)

    def proto_disabled(self,xml,target):
        try:
            root = xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        num_suites = 0
        for suites in root.findall('.//acceptedCipherSuites'):
            num_suites += len(suites)
        for suites in root.findall('.//preferredCipherSuite'):
            num_suites += len(suites)
        # If there are zero accepted and preferred suites, connection was
        # not successful
        assert num_suites == 0, \
            "An acceptable cipher suite was found (= a connection was made)."

    # check that time is more than validity start time
    def check_cert_begin(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        notbefore_string = root.find('.//validity/notBefore').text
        notbefore = dateutil.parser.parse(notbefore_string)
        assert notbefore <= datetime.utcnow().replace(tzinfo=pytz.utc), \
            "Server certificate is not yet valid (begins %s)" % notbefore_string

    # check that certificate is still valid at least for {days}
    def check_cert_end(self, days):
        #days = int(days)
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        notafter_string = root.find('.//validity/notAfter').text
        notafter = dateutil.parser.parse(notafter_string)
        notafter = notafter - dateutil.relativedelta.relativedelta(days=+days)
        assert notafter >= datetime.utcnow().replace(tzinfo=pytz.utc), \
            "Server certificate will not be valid in %s days (expires %s)" % \
            (days, notafter_string)


    # ensure compression is disabled
    def compression_disabled(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        compr = root.findall('.//compressionMethod')
        compression = False
        for comp_method in compr:
            if comp_method.get('isSupported') != 'False':
                compression = True
        assert compression is False, "Compression is enabled"


    # check secure renegotiation
    def secure_reneg(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        reneg = root.find('.//reneg/sessionRenegotiation')
        assert reneg is not None, \
            "Renegotiation is not supported"
        assert reneg.get('canBeClientInitiated') == 'False', \
            "Client side renegotiation is enabled (shouldn't be)"
        assert reneg.get('isSecure') == 'True', \
            "Secure renegotiation is not supported (should be)"

    # check preferred suites
    def cipher_suites_preferred(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        acceptable_suites = self.config.suites_preferred
        acceptable_suites_regex = "(" + ")|(".join(acceptable_suites) + ")"
        # The regex must match the preferred suite for every protocol
        found = True
        accepted_suites = root.findall('.//preferredCipherSuite/cipherSuite')
        for accepted_suite in accepted_suites:
            if re.search(acceptable_suites_regex, accepted_suite.get("name")) is None:
                found = False
        assert found, "Not all of the preferred cipher suites were on our list"


    def cipher_suites_disabled(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")

        suite_blacklist_regex = "(" + ")|(".join(self.config.suites_disabled) + ")"
        # The regex should not match to any accepted suite for any protocol
        passed = True
        found_list = ""
        for accepted_suites in root.findall('.//acceptedCipherSuites'):
            for suite in accepted_suites:
                if re.search(suite_blacklist_regex, suite.get("name")) is not None:
                    passed = False
                    found_list = found_list + "%s " % suite.get("name")
        assert passed, "Blacklisted cipher suite(s) found: %s" % found_list

    def cipher_suites_enabled(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        acceptable_suites = self.config.suites_enabled

        acceptable_suites_regex = "(" + ")|(".join(acceptable_suites) + ")"
        # The regex must match at least once for some protocol
        found = False
        for accepted_suites in root.findall('.//acceptedCipherSuites'):
            for suite in accepted_suites:
                if re.search(acceptable_suites_regex, suite.get("name")) is not None:
                    found = True
        assert found, "None of listed cipher suites were enabled"

    # TLS headers are set to strict
    def strict_tls_headers(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        hsts = root.find('.//httpStrictTransportSecurity')
        assert hsts.get('isSupported') == 'True', \
            "HTTP Strict Transport Security header not observed"
    
    # Heartbleed check
    def heartbleed(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        heartbleed = root.find('.//openSslHeartbleed')
        assert heartbleed.get('isVulnerable') == 'False', \
            "Server is vulnerable for Heartbleed"
    
    # check that the certrificate doesn't use SHA1
    def sha1(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        sha1 = root.find('.//certificateChain')
        assert sha1.get('hasSha1SignedCertificate') == "False", \
            "Server is affected by SHA-1 deprecation (sunset)"
    
    # D-H group size is at least {groupsize}
    def check_dh_group_size(self, groupsize):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        keyexchange = root.find(".//keyExchange")
        if keyexchange is None:
        # Kudos bro!
            return
        keytype = keyexchange.get('Type')
        realgroupsize = keyexchange.get('GroupSize')
        if keytype == 'DH':
            assert groupsize <= int(realgroupsize), \
                "D-H group size less than %d" % groupsize
    
    # check that the certificate is in major root CA trust stores
    def trusted_ca(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        certificate = root.findall(".//pathValidation")
        for pathvalidation in certificate:
            assert pathvalidation.get("validationResult") == 'ok', "Certificate not in trust store %s" % pathvalidation.get(
                "usingTrustStore")
    
    
    # check that certificate has a matching hostname
    def matching_hostname(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        certificate = root.find(".//hostnameValidation")
        assert certificate.get("certificateMatchesServerHostname") == 'True', \
            "Certificate subject does not match host name"
        
    # ensure that the public key of the cert is at least {keysize} bits
    def check_public_key_size(self, keysize):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        publickeysize = root.find(".//publicKeySize").text
        assert int(keysize) <= int(publickeysize), \
            "Public key size %s less than %s" % (publickeysize,keysize)


class Target(object):
    def __init__(self,host,port,protocols):
        self.host = host
        self.port = port
        # protocols that should be enabled or disabled
        self.protocols = protocols

class MittnTLSChecker(object):
    def __init__(self,config_path="./mittn.conf",sslyze_path=None,
            config=None, checker=None):
        self.config = config or Config(config_path)
        self.sslyze = PythonSslyze(self.config.sslyze_path)
        self.checker = checker or Checker()
        self.checker.config = self.config

    def run(self,host,port=443):
        target = Target(host,port,self.config.protocols)

        # puts results into target.xmloutputs[proto] dict
        self.sslyze.run(target)

        self.checker.run(target)
