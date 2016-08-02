import re
# The following for calculating validity times from potentially
# locale specific timestamp strings
import pytz
import dateutil.parser
import dateutil.relativedelta
from datetime import datetime

class Check(object):
    """
A class for the check object which holds all relevant information.
State is initalized as 'Skipped' and changed accordingly when checks are run.
    """
    def __init__(self,check,title,description):
        self.check = check
        self.title = title
        self.description = description
        self.state = 'SKIP'

    def __repr__(self):
        return self.state + ": " + self.title + "\n\t" + self.description

class Checker(object):
    """ Contains all checks to be run against the output of PythonSslyze.
        Run method returns a tuple with arrays for passed, failed and skipped tests.
    """
    def __init__(self,config):
        self.config = config
        self.checks = [
                Check(self.proto_enabled,
                    "Protocol is enabled",
                    ""),
                Check(self.check_cert_begin,
                    "Certificate begins before now",
                    ""),
                Check(self.check_cert_end,
                    "Certificate expiration",
                    "Certificate is valid for at least %d days" % self.config.days_valid),
                Check(self.compression_disabled,
                    "Compression is disabled",
                    ""),
                Check(self.secure_reneg,
                    "Secure renegotation is enforced",
                    ""),
                Check(self.cipher_suites_preferred,
                    "Preferred cipher suites",
                    ""),
                Check(self.cipher_suites_disabled,
                    "Disabled cipher suites",
                    ""),
                Check(self.cipher_suites_enabled,
                    "Enabled cipher suites",
                    ""),
                Check(self.strict_tls_headers,
                    "Strict TLS headers",
                    ""),
                Check(self.heartbleed,
                    "Heartbleed",
                    ""),
                Check(self.sha1,
                    "Sha1",
                    ""),
                Check(self.check_dh_group_size,
                    "DH-group size",
                    ""),
                Check(self.trusted_ca,
                    "Trusted ca-certificate",
                    ""),
                Check(self.matching_hostname,
                    "Certificate with matching hostname",
                    ""),
                Check(self.check_public_key_size,
                    "Public key size",
                    ""),
        ]

    def run(self,target):
        if not self.config:
            raise ValueError("Missing configuration for Tlschecker")

        checks = []
        for proto in target.protocols.keys():
            # get results from sslyze for this protocol
            self.xml = target.xmloutputs[proto]
            self.proto = proto
            if target.protocols[proto]:
                # if protocol should be enabled
                for c in self.checks:
                    try:
                        result = c.check()
                        # Get the message from failure
                        if type(result) is tuple:
                            result, c.description = result
                        if result:
                            c.state = 'PASS'
                        else:
                            c.state = 'FAIL'
                    except ConnectionError as e:
                        c.description = e
                        c.state = 'FAIL'
                        break
            else:
            # if protocol should be disabled
                c = Check(self.proto_disabled,
                        "Protocol is disabled",
                        "")
                result = c.check()
                if type(result) is tuple:
                    result, c.description = result
                if result:
                    c.state = 'PASS'
                else:
                    c.state = 'FAIL'
                checks.append(c)
            
        return self.checks + checks

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
        days = self.config.days_valid
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
        return (True,"Compression is not supported on the server")


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
        if not len(self.config.suites_preferred):
            return True
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
            return (False,"Not all of the preferred cipher suites were on our list")
        return (True,"All of the preferred suites were on our list")


    def cipher_suites_disabled(self):
        if not len(self.config.suites_disabled):
            return True
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
        if not passed:
            return (False,"Blacklisted cipher suite(s) found: %s" % found_list)
        return (True,"No blacklisted suites amongst accepted cipher suites")

    def cipher_suites_enabled(self):
        if not len(self.config.suites_enabled):
            return True
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
            return (False,"Enabled suites contained suites not in our list")
        return (True,"All accepted cipher suites were in our enabled list")

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
        heartbleed = root.find('.//openSslHeartbleed')
        if heartbleed.get('isVulnerable') != 'False':
            return (False,"Server is vulnerable for Heartbleed")
        return (True,"Server is not vulnerable to Heartbleed")
    
    # check that the certrificate doesn't use SHA1
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
        groupsize = self.config.dh_group_size
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        keyexchange = root.find(".//keyExchange")
        if keyexchange is None:
        # Kudos bro!
            return True
        keytype = keyexchange.get('Type')
        realgroupsize = keyexchange.get('GroupSize')
        if keytype == 'DH':
            if groupsize <= int(realgroupsize):
                return (False,"D-H group size less than %d" % groupsize)
        return (True,"D-H group size is %d which is at least %d" % \
                (groupsize, int(realgroupsize)))
    
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
        keysize = self.config.public_key_size
        try:
            root = self.xml.getroot()
        except AttributeError:
            raise ValueError("No stored TLS connection result set was found.")
        publickeysize = root.find(".//publicKeySize").text
        if int(keysize) > int(publickeysize):
            return (False,"Public key size %s less than %d" % (publickeysize,keysize))
        return (True,"Public key size %s is not less than %d" % (publickeysize,keysize))

