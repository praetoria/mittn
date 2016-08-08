import re
# The following for calculating validity times from potentially
# locale specific timestamp strings
import pytz
import dateutil.parser
import dateutil.relativedelta
from datetime import datetime
import xml.etree.ElementTree as ET

class Check(object):
    """
A class for the check object which holds all relevant information.
State is initalized as skipped and changed accordingly when checks are run.
    """
    def __init__(self,title,proto):
        self.title = title
        self.description = ""
        self.state = "SKIP"
        self.proto = proto

    def __repr__(self):
        return self.state + ": " + self.proto + " " + self.title + "\n\t" + self.description

class TlsChecker(object):
    """ Contains all checks to be run against the output of PythonSslyze.
        Run method returns a tuple with three lists of Check objects,
        succeeded, failed and skipped tests
    """
    def __init__(self,config):
        self.config = config
        # The check functions below return a tuple with
        # a boolean, True if the test was passed,
        # and a description of what failed/succeeded in the test
        self.checks = [
                (self.proto_enabled,
                    "Protocol is enabled"),
                (self.check_cert_begin,
                    "Certificate begins before now"),
                (self.check_cert_end,
                    "Certificate expiration"),
                (self.compression_disabled,
                    "Compression is disabled"),
                (self.secure_reneg,
                    "Secure renegotiation"),
                (self.cipher_suites_preferred,
                    "Preferred cipher suites"),
                (self.cipher_suites_disabled,
                    "Blacklisted cipher suites"),
                (self.cipher_suites_enabled,
                    "Enabled cipher suites"),
                (self.strict_tls_headers,
                    "Strict TLS headers"),
                (self.heartbleed,
                    "Heartbleed"),
                (self.sha1,
                    "SHA1"),
                (self.check_dh_group_size,
                    "DH-group size"),
                (self.trusted_ca,
                    "Trusted ca-certificate"),
                (self.matching_hostname,
                    "Certificate with matching hostname"),
                (self.check_public_key_size,
                    "Public key size"),
        ]

    def run(self,xmloutputs):
        if not self.config:
            raise ValueError("Missing configuration for Tlschecker")

        checks = []
        for proto in self.config.protocols_enabled:
            self.xml = xmloutputs[proto]
            self.proto = proto
            # if protocol should be enabled
            skip_rest = False
            for check,title in self.checks:
                c = Check(title,proto)
                checks.append(c)
                if skip_rest:
                    continue
                try:
                    result = check()
                    # Get the message from failure
                    if type(result) is tuple:
                        result, c.description = result
                    if result:
                        c.state = 'PASS'
                    else:
                        c.state = 'FAIL'
                except ConnectionError as e:
                    c.description = str(e)
                    c.state = 'FAIL'
                    skip_rest = True
                except ValueError as e:
                # probably failed to read the xml
                    print(ET.dump(self.xml))
                    print(str(e))

        for proto in self.config.protocols_disabled:
            self.xml = xmloutputs[proto]
            self.proto = proto
            c = Check("Protocol is disabled",proto)
            result = self.proto_disabled()
            if type(result) is tuple:
                result, c.description = result
            if result:
                c.state = 'PASS'
            else:
                c.state = 'FAIL'
            checks.append(c)

        ret = {"PASS":[], "FAIL":[], "SKIP":[]}
        for c in checks:
            ret[c.state].append(c)
        return (ret["PASS"],ret["FAIL"],ret["SKIP"])

    # make sure connection is successful
    def proto_enabled(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")

        # The connection target should have been resolved
        # The .//foo notation is an Xpath
        if len(root.findall('.//invalidTargets')) != 1:
            raise ConnectionError("Target system did not resolve or could not connect")
        for error in root.findall('.//errors'):
            # There should be no connection errors
            if len(error) != 0:
                raise ConnectionError("Errors found creating a connection to ")
        num_acceptedsuites = 0
        for acceptedsuites in root.findall('.//acceptedCipherSuites'):
            num_acceptedsuites += len(acceptedsuites)
        # If there are more than zero accepted suites (for any enabled protocol)
        # the connection was successful
        if num_acceptedsuites == 0:
            raise ConnectionError("No acceptable cipher suites found.")
        return (True,"Protocol %s is enabled" % self.proto)

    def proto_disabled(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        num_suites = 0
        for suites in root.findall('.//acceptedCipherSuites'):
            num_suites += len(suites)
        for suites in root.findall('.//preferredCipherSuite'):
            num_suites += len(suites)
        # If there are zero accepted and preferred suites, connection was
        # not successful
        if num_suites != 0:
            return (False,"An acceptable cipher suite was found (= a connection was made).")
        return (True,"Protocol %s is disabled" % self.proto)

    # check that time is more than validity start time
    def check_cert_begin(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        notbefore_string = root.find('.//validity/notBefore').text
        notbefore = dateutil.parser.parse(notbefore_string)
        if notbefore > datetime.utcnow().replace(tzinfo=pytz.utc):
            return (False,"Server certificate is not yet valid (begins %s)" % notbefore_string)
        return (True,"Server certificate is valid from %s" % notbefore_string)

    # check that certificate is still valid at least for {days}
    def check_cert_end(self):
        days = int(self.config.days_valid)
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        notafter_string = root.find('.//validity/notAfter').text
        notafter = dateutil.parser.parse(notafter_string)
        notafter = notafter - dateutil.relativedelta.relativedelta(days=+days)
        if notafter < datetime.utcnow().replace(tzinfo=pytz.utc):
            return (False,
                    "Server certificate will not be valid in %d days (expires %s)" % \
                    (days, notafter_string))
        return (True,
                "Server certificate is still valid for at least %d days (expires %s)" % \
                (days, notafter_string))


    # ensure compression is disabled
    def compression_disabled(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        compr = root.findall('.//compressionMethod')
        for comp_method in compr:
            if comp_method.get('isSupported') != 'False':
                return (False,"Compression is enabled")
        return (True,"Compression is disabled on the server")


    # check secure renegotiation
    def secure_reneg(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        reneg = root.find('.//reneg/sessionRenegotiation')
        if reneg is None:
            return (False,"Renegotiation is not supported")
        if reneg.get('canBeClientInitiated') != 'False':
            return (False,"Client side renegotiation is enabled (shouldn't be)")
        if reneg.get('isSecure') != 'True':
            return (False,"Secure renegotiation is not supported (should be)")
        return (True,"Secure renegotiation is supported on the server")

    # check preferred suites
    def cipher_suites_preferred(self):
        if not self.config.suites_preferred:
            return (True,"No cipher suites to check")
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
        if not found:
            return (False,"Preferred suites contained suites not on our list")
        return (True,"All of the preferred suites were on our list")


    def cipher_suites_disabled(self):
        if not self.config.suites_blacklisted:
            return (True,"No cipher suites to check")
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")

        suite_blacklist_regex = "(" + ")|(".join(self.config.suites_blacklisted) + ")"
        # The regex should not match to any accepted suite for any protocol
        passed = True
        found_list = ""
        for accepted_suites in root.findall('.//acceptedCipherSuites'):
            for suite in accepted_suites:
                if re.search(suite_blacklist_regex, suite.get("name")) is not None:
                    passed = False
                    found_list = found_list + "%s " % suite.get("name")
        if not passed:
            return (False,"Blacklisted cipher suite(s) found: %s" % found_list)
        return (True,"No blacklisted suites amongst accepted cipher suites")

    def cipher_suites_enabled(self):
        if not self.config.suites_enabled:
            return (True,"No cipher suites to check")
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
        if not found: 
            return (False,"Enabled suites contained suites not on our list")
        return (True,"All accepted cipher suites were on our enabled list")

    # TLS headers are set to strict
    def strict_tls_headers(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        hsts = root.find('.//httpStrictTransportSecurity')
        if hsts.get('isSupported') != 'True':
            return (False,"HTTP Strict Transport Security header not observed")
        return (True,"HTTP Strict Transport Security header is supported")
    
    # Heartbleed check
    def heartbleed(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        heartbleedstatus = root.find('.//openSslHeartbleed')
        if heartbleedstatus is None:
            raise ValueError("No openSslHeartbleed section found in the xml")
        if heartbleedstatus.get('isVulnerable') != 'False':
            return (False,"Server is vulnerable for Heartbleed")
        return (True,"Server is not vulnerable to Heartbleed")
    
    # check that the certificate doesn't use SHA1
    def sha1(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        sha1 = root.find('.//certificateChain')
        if sha1.get('hasSha1SignedCertificate') == "False":
            return (False,"Server is affected by SHA-1 deprecation (sunset)")
        return (True,"Server is not affected by SHA-1 deprecation (sunset)")
    
    # D-H group size is at least {groupsize}
    def check_dh_group_size(self):
        groupsize = int(self.config.dh_group_size)
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        keyexchange = root.find(".//keyExchange")
        if keyexchange is None:
        # Kudos bro!
            return (True,"No Key Exchange found")
        keytype = keyexchange.get('Type')
        realgroupsize = keyexchange.get('GroupSize')
        if keytype == 'DH':
            if groupsize <= int(realgroupsize):
                return (True,"D-H group size is %d which is at least %d" % \
                    (int(realgroupsize),groupsize))
            return (False,"D-H group size less than %d" % groupsize)
        return (True,"No DH-key found")
    
    # check that the certificate is in major root CA trust stores
    def trusted_ca(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            if False:
                return (False,"No stored TLS connection result set was found.")
            return True
        certificate = root.findall(".//pathValidation")
        for pathvalidation in certificate:
            if pathvalidation.get("validationResult") != 'ok':
                return (False,"Certificate not in trust store %s" % \
                        pathvalidation.get("usingTrustStore"))
        return (True,"Certificate is in a trust store (%s)" % \
                pathvalidation.get("usingTrustStore"))
    
    
    # check that certificate has a matching hostname
    def matching_hostname(self):
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        certificate = root.find(".//hostnameValidation")
        if certificate.get("certificateMatchesServerHostname") != 'True':
            return (False,"Certificate subject does not match host name")
        return (True,"Certificate matches the server's hostname")
        
    # ensure that the public key of the cert is at least {keysize} bits
    def check_public_key_size(self):
        keysize = int(self.config.public_key_size)
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        publickeysize = root.find(".//publicKeySize").text
        if int(keysize) > int(publickeysize):
            return (False,"Public key size %s less than %d" % (publickeysize,keysize))
        return (True,"Public key size %s is not less than %d" % (publickeysize,keysize))

