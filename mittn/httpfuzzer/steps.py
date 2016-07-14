"""mittn httpfuzzer class"""

"""
Copyright (c) 2014 F-Secure
See LICENSE for details
"""

from mittn.httpfuzzer.static_anomalies import *
from mittn.httpfuzzer.fuzzer import *
from mittn.httpfuzzer.injector import *
from mittn.httpfuzzer.number_ranges import *
from mittn.httpfuzzer.url_params import *
import mittn.httpfuzzer.dbtools as fuzzdb
import json
import urlparse2
import subprocess
import re
from mittn.loadconfig import LoadConfig

class httpfuzzer:
    def __init__(self):    
        self.context = LoadConfig("httpfuzzer")
        self.check_baseline_database()
        self.check_radamsa_installation()
        self.check_valid_case_instrumentation()
        self.check_timeout()

    def add_target(self, uri, method, submission, type):
        self.store_uri(uri)
        self.store_submission(submission, method, type)

    def fuzz(self):
        self.perform_static_injection()
        self.store_bad_return_codes()
        self.report_findings()

#############################################
### functions related to setup the httpfuzzer        
#############################################

    def check_baseline_database(self):
        """Test that we can connect to a database. As a side effect,
        open_database() also creates the necessary table(s) that are
        required."""
        if hasattr(self.context, 'dburl') is False:
            assert False, "Database URI not specified"
        dbconn = fuzzdb.open_database(self.context)
        if dbconn is None:
            assert False, "Cannot open database %s" % self.context.dburl
        dbconn.close()

#@given(u'an authentication flow id "{auth_id}"')
#def step_impl(context, auth_id):
#    """Store the authentication flow identifier. Tests in the feature file
#    can use different authentication flows, and this can be used to
#    select one of them in authenticate.py.
#    """
#
#    context.authentication_id = auth_id
#    assert True


    def check_valid_case_instrumentation(self):
        """Make a note of the fact that we would like to do valid case
        instrumentation."""
    
        self.context.valid_cases = unpack_integer_range(self.context.valid_cases)
        self.context.valid_case_instrumentation = True

    def check_timeout(self):
        """Store the timeout value.
        """
        self.context.timeout = float(self.context.timeout)
        if self.context.timeout < 0:
            assert False, "Invalid timeout value %s" % self.context.timeout

    def check_radamsa_installation(self):
        """Check for a working Radamsa installation."""

        if self.context.radamsa_location is None:
            assert False, "The feature file requires Radamsa, but the path is " \
                          "undefined."
        try:
            subprocess.check_output([self.context.radamsa_location, "--help"],
                                stderr=subprocess.STDOUT)
        except (subprocess.CalledProcessError, OSError) as error:
            assert False, "Could not execute Radamsa from %s: %s" % (self.context.radamsa_location, error)

################################################
### valid case setup functions      
################################################

    def store_uri(self, uri):
        """Store the target URI that we are injecting or fuzzing."""

        # The target URI needs to be a string so it doesn't trigger Unicode
        # conversions for stuff we concatenate into it later; the Python
        # Unicode library will barf on fuzzed data
        self.context.targeturi = str(uri)

    def store_submission(self, submission, method, type):
        """For static injection, store a submission where elements are replaced with
        injections and test it once. This is also used for the valid case
        instrumentation.
        """

        if hasattr(self.context, 'timeout') is False:
            self.context.timeout = 5  # Sensible default
        if hasattr(self.context, 'targeturi') is False:
            assert False, "Target URI not specified"

        # Unserialise into a data structure and store in a list
        # (one valid case is just a special case of providing
        # several valid cases)
        if   type == 'urlencode':
            self.context.submission = [urlparse2.parse_qs(submission)]
            self.context.content_type = 'application/x-www-form-urlencoded; charset=utf-8'
        elif type == 'url-parameters':
            self.context.submission = [url_to_dict(submission)]
            self.context.content_type = 'application/x-www-form-urlencoded; charset=utf-8'
        elif type == 'json':
            self.context.submission = [json.loads(submission)]
            self.context.content_type = 'application/json'
        
        self.context.type = type  # Used downstream for selecting encoding
        self.context.submission_method = method
        test_valid_submission(self.context)


#@given(u'valid JSON submissions using "{method}" method')
#def step_impl(context, method):
#    """Store a list of valid JSON submissions (used for valid cases
#    for fuzz generation
#    """
#
#    if hasattr(context, 'timeout') is False:
#        context.timeout = 5  # Sensible default
#    if hasattr(context, 'targeturi') is False:
#        assert False, "Target URI not specified"
#    context.submission = []
#    context.submission_method = method
#    context.type = 'json'  # Used downstream for selecting encoding
#    context.content_type = 'application/json'
#    # Add all valid cases into a list as unserialised data structures
#    for row in context.table:
#        context.submission.append(json.loads(row['submission']))
#    test_valid_submission(context)
#    assert True
#
#
#@given(u'valid form submissions using "{method}" method')
#def step_impl(context, method):
#    """Store a list of valid form submissions (used for valid cases for
#    fuzz generation)
#    """
#
#    if hasattr(context, 'timeout') is False:
#        context.timeout = 5  # Sensible default
#    if hasattr(context, 'targeturi') is False:
#        assert False, "Target URI not specified"
#    context.submission = []
#    context.submission_method = method
#    context.type = 'urlencode'  # Used downstream for selecting encoding
#    context.content_type = 'application/x-www-form-urlencoded; charset=utf-8'
#    # Add all valid cases into a list as unserialised data structures
#    for row in context.table:
#        context.submission.append(urlparse2.parse_qs(row['submission']))
#    test_valid_submission(context)
#    assert True
#
#
#@given(u'valid url parameters')
#def step_impl(context, method):
#    """Store a list of valid url parameters (used for valid cases for
#    fuzz generation)
#    """
#
#    if hasattr(context, 'timeout') is False:
#        context.timeout = 5  # Sensible default
#    if hasattr(context, 'targeturi') is False:
#        assert False, "Target URI not specified"
#    context.submission = []
#    context.submission_method = 'GET'
#    context.type = 'url-parameters'  # Used downstream for selecting encoding
#    context.content_type = 'application/x-www-form-urlencoded; charset=utf-8'
#    # Add all valid cases into a list as unserialised data structures
#    for row in context.table:
#        context.submission.append(url_to_dict(row['submission']))
#    test_valid_submission(context)
#    assert True
#
#

#################################################
# performing injections and analyzing the results
#################################################

    def perform_fuzz_injection(self, no_of_cases):
        """perform fuzzing and fuzz case injection
        """

        self.context.new_findings = 0
        # Collect the valid keys/values from the valid examples
        valuelist = {}
        for submission in self.context.submission:
            valuelist = collect_values(submission, valuelist)
        # Create the list of fuzz injections using a helper generator
        fuzzed_anomalies_dict = fuzz_values(valuelist, no_of_cases,
                                            self.context.radamsa_location)
        injection_list = anomaly_dict_generator_fuzz(fuzzed_anomalies_dict)
        self.context.responses = inject(self.context, injection_list)

    def perform_static_injection(self): 
        """Perform injection of static anomalies
        """
        self.context.new_findings = 0
        # Create the list of static injections using a helper generator
        injection_list = anomaly_dict_generator_static(anomaly_list)
        self.context.responses = inject(self.context, injection_list)

    def store_bad_return_codes(self):
        """Go through responses and store any with suspect return codes
        into the database
        """
    
        disallowed_returncodes = unpack_integer_range(self.context.returncode_list)
        new_findings = 0
        for response in self.context.responses:
            if response['resp_statuscode'] in disallowed_returncodes:
                if fuzzdb.known_false_positive(self.context, response) is False:
                    fuzzdb.add_false_positive(self.context, response)
                    new_findings += 1
        if new_findings > 0:
            self.context.new_findings += new_findings

    def store_timed_out_responses(self):
        """Go through responses and save any that timed out into the database
        """
    
        new_findings = 0
        for response in self.context.responses:
            if response.get('server_timeout') is True:
                if fuzzdb.known_false_positive(self.context, response) is False:
                    fuzzdb.add_false_positive(self.context, response)
                    new_findings += 1
        if new_findings > 0:
            self.context.new_findings += new_findings
    
    def store_protocol_errors(self):
        """Go through responses and store any with HTTP protocol errors
        (as caught by Requests) into the database
        """
    
        new_findings = 0
        for response in self.context.responses:
            if response.get('server_protocol_error') is not None:
                if fuzzdb.known_false_positive(self.context, response) is False:
                    fuzzdb.add_false_positive(self.context, response)
                    new_findings += 1
        if new_findings > 0:
            self.context.new_findings += new_findings
    
    def store_bad_strings(self):
        """Go through responses and store any that contain a string from
        user-supplied list of strings into the database
        """
    
        # Create a regex from the error response list
        error_list = []
        for row in self.context.table:
            error_list.append(row['string'])
        error_list_regex = "(" + ")|(".join(error_list) + ")"
    
        # For each response, check that it isn't in the error response list
        new_findings = 0
        for response in self.context.responses:
            if re.search(error_list_regex, response.get('resp_body'),
                         re.IGNORECASE) is not None:
                response['server_error_text_detected'] = True
                if fuzzdb.known_false_positive(self.context, response) is False:
                    fuzzdb.add_false_positive(self.context, response)
                    new_findings += 1
        if new_findings > 0:
            self.context.new_findings += new_findings

    def report_findings(self):
        """Check whether we stored any new findings
        """
        if self.context.new_findings > 0:
            assert False, "%s new findings were found." % self.context.new_findings
        old_findings = fuzzdb.number_of_new_in_database(self.context)
        if old_findings > 0:
            assert False, "No new findings found, but %s unprocessed findings from past runs found in database." % old_findings
