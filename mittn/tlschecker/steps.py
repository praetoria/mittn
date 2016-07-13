# pylint: disable=E0602,E0102

"""
Copyright (c) 2013-2014 F-Secure
See LICENSE for details
"""

from subprocess import check_output
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

from mittn.loadconfig import LoadConfig

class tlschecker:
    def __init__(self):
        self.context = LoadConfig("tlschecker")
        self.sslyze_version_check()

    def set(self,settings = {}):
        for key in settings.keys():
            setattr(self.context,key,settings[key])

    def run(self,host,port):
        self.context.host = host
        self.context.port = port
        if hasattr(self,"disabled_protocols") is False:
            self.disabled_protocols = ["SSLv2","SSLv3"]

        for proto in self.disabled_protocols:
            self.sslyze_run(proto)
            self.proto_disabled_check()
        self.sslyze_run("TLSv1_2")
        self.proto_enabled_check()
        self.cert_begin_check()
        self.cert_end_check(30)
        self.compression_disabled_check()
        self.secure_reneg_check()
        self.cipher_suites_disabled_check()
        self.cipher_suites_enabled_check()
        self.preferred_suites_check()
        self.strict_tls_headers_check()
        self.heartbleed_check()
        self.sha1_check()
        self.dh_group_size_check(2048)
        self.trusted_ca_check()
        self.cert_matching_hostname_check()
        self.public_key_size_check(2048)

    #@step('sslyze is correctly installed')
    def sslyze_version_check(self):
        context = self.context
        context.output = check_output([context.sslyze_location, '--version'])
        assert "0.13.6" in context.output, "SSLyze version 0.13.6 is required"

    #@step(u'a "{proto}" connection is made')
    def sslyze_run(self, proto):
        context = self.context
        host = context.host
        port = context.port
        xmloutfile = NamedTemporaryFile(delete=False)
        xmloutfile.close()  # Free the lock on the XML output file
        context.output = check_output([context.sslyze_location, "--%s" % proto.lower(),
                                    "--compression", "--reneg",
                                    "--heartbleed",
                                    "--xml_out=" + xmloutfile.name,
                                    "--certinfo_full",
                                    "--hsts",
                                    "--http_get",
                                    "--sni=%s" % host,
                                    "%s:%s" % (host, port)])
        context.xmloutput = ET.parse(xmloutfile.name)
        os.unlink(xmloutfile.name)
    
    #@step(u'a TLS connection can be established')
    def proto_enabled_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        # The connection target should have been resolved
        # The .//foo notation is an Xpath
        assert len(root.findall('.//invalidTargets')) == 1, \
            "Target system did not resolve or could not connect"
        for error in root.findall('.//errors'):
            # There should be no connection errors
            assert len(error) == 0, \
                "Errors found creating a connection to %s:%s" % (context.host, context.port)
        num_acceptedsuites = 0
        for acceptedsuites in root.findall('.//acceptedCipherSuites'):
            num_acceptedsuites += len(acceptedsuites)
        # If there are more than zero accepted suites (for any enabled protocol)
        # the connection was successful
        assert num_acceptedsuites > 0, \
            "No acceptable cipher suites found at %s:%s" % (context.host, context.port)

    #@step(u'a TLS connection cannot be established')
    def proto_disabled_check(self):
        try:
            root = self.context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        num_suites = 0
        for suites in root.findall('.//acceptedCipherSuites'):
            num_suites += len(suites)
        for suites in root.findall('.//preferredCipherSuite'):
            num_suites += len(suites)
        # If there are zero accepted and preferred suites, connection was
        # not successful
        assert num_suites == 0, \
            "An acceptable cipher suite was found (= a connection was made)."

    #@step(u'Time is more than validity start time')
    def cert_begin_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        notbefore_string = root.find('.//validity/notBefore').text
        notbefore = dateutil.parser.parse(notbefore_string)
        assert notbefore <= datetime.utcnow().replace(tzinfo=pytz.utc), \
            "Server certificate is not yet valid (begins %s)" % notbefore_string


    #@step(u'Time plus "{days}" days is less than validity end time')
    def cert_end_check(self, days):
        context = self.context
        #days = int(days)
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        notafter_string = root.find('.//validity/notAfter').text
        notafter = dateutil.parser.parse(notafter_string)
        notafter = notafter - dateutil.relativedelta.relativedelta(days=+days)
        assert notafter >= datetime.utcnow().replace(tzinfo=pytz.utc), \
            "Server certificate will not be valid in %s days (expires %s)" % \
            (days, notafter_string)

    #@step(u'compression is not enabled')
    def compression_disabled_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        compr = root.findall('.//compressionMethod')
        compression = False
        for comp_method in compr:
            if comp_method.get('isSupported') != 'False':
                compression = True
        assert compression is False, "Compression is enabled"


    #@step(u'secure renegotiation is supported')
    def secure_reneg_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        reneg = root.find('.//reneg/sessionRenegotiation')
        assert reneg is not None, \
            "Renegotiation is not supported"
        assert reneg.get('canBeClientInitiated') == 'False', \
            "Client side renegotiation is enabled (shouldn't be)"
        assert reneg.get('isSecure') == 'True', \
            "Secure renegotiation is not supported (should be)"

    #@step(u'the following cipher suites are disabled')
    def cipher_suites_disabled_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."

        suite_blacklist_regex = "(" + ")|(".join(context.suite_blacklist) + ")"
        # The regex should not match to any accepted suite for any protocol
        passed = True
        found_list = ""
        for accepted_suites in root.findall('.//acceptedCipherSuites'):
            for suite in accepted_suites:
                if re.search(suite_blacklist_regex, suite.get("name")) is not None:
                    passed = False
                    found_list = found_list + "%s " % suite.get("name")
        assert passed, "Blacklisted cipher suite(s) found: %s" % found_list


    #@step(u'at least one the following cipher suites is enabled')
    def cipher_suites_enabled_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        acceptable_suites = context.suite_whitelist

        acceptable_suites_regex = "(" + ")|(".join(acceptable_suites) + ")"
        # The regex must match at least once for some protocol
        found = False
        for accepted_suites in root.findall('.//acceptedCipherSuites'):
            for suite in accepted_suites:
                if re.search(acceptable_suites_regex, suite.get("name")) is not None:
                    found = True
        assert found, "None of listed cipher suites were enabled"

    #@step(u'one of the following cipher suites is preferred')
    def preferred_suites_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        acceptable_suites = context.preferred_suites
        acceptable_suites_regex = "(" + ")|(".join(acceptable_suites) + ")"
        # The regex must match the preferred suite for every protocol
        found = True
        accepted_suites = root.findall('.//preferredCipherSuite/cipherSuite')
        for accepted_suite in accepted_suites:
            if re.search(acceptable_suites_regex, accepted_suite.get("name")) is None:
                found = False
        assert found, "None of the listed cipher suites were preferred"


    #@step(u'Strict TLS headers are seen')
    def strict_tls_headers_check(context):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        hsts = root.find('.//httpStrictTransportSecurity')
        assert hsts.get('isSupported') == 'True', \
            "HTTP Strict Transport Security header not observed"
    
    #@step(u'server has no Heartbleed vulnerability')
    def heartbleed_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        heartbleed = root.find('.//openSslHeartbleed')
        assert heartbleed.get('isVulnerable') == 'False', \
            "Server is vulnerable for Heartbleed"
    
    #@step(u'certificate does not use SHA-1')
    def sha1_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        sha1 = root.find('.//chromeSha1Deprecation')
        assert sha1.get('isServerAffected') == "False", \
            "Server is affected by SHA-1 deprecation (sunset)"
    
    #@step(u'the D-H group size is at least "{groupsize}" bits')
    def dh_group_size_check(self, groupsize):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        keyexchange = root.find(".//keyExchange")
        if keyexchange is None:
        # Kudos bro!
            return
        keytype = keyexchange.get('Type')
        realgroupsize = keyexchange.get('GroupSize')
        if keytype == 'DH':
            assert groupsize <= int(realgroupsize), \
                "D-H group size less than %d" % groupsize
    
    #@step(u'the certificate is in major root CA trust stores')
    def trusted_ca_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        certificate = root.findall(".//pathValidation")
        for pathvalidation in certificate:
            assert pathvalidation.get("validationResult") == 'ok', "Certificate not in trust store %s" % pathvalidation.get(
                "usingTrustStore")
    
    
    #@step(u'the certificate has a matching host name')
    def cert_matching_hostname_check(self):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        certificate = root.find(".//hostnameValidation")
        assert certificate.get("certificateMatchesServerHostname") == 'True', \
            "Certificate subject does not match host name"
        
    #@step(u'the public key size is at least "{keysize}" bits')
    def public_key_size_check(self, keysize):
        context = self.context
        try:
            root = context.xmloutput.getroot()
        except AttributeError:
            assert False, "No stored TLS connection result set was found."
        publickeysize = root.find(".//publicKeySize").text
        assert int(keysize) <= int(publickeysize[0]), \
            "Public key size less than %s" % keysize
