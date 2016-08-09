# pylint: disable=E0602,E0102

"""
Copyright (c) 2013-2014 F-Secure
See LICENSE for details

Burp and Burp Suite are trademarks of Portswigger, Ltd.
"""

from behave import *
import shlex
import subprocess
import select
import requests
import json
import time
import re
import logging
import os
from mittn.scanner.proxy_comms import *
import mittn.scanner.dbtools as scandb
# Import positive test scenario implementations
from features.scenarios import *

class pythonBurp():
    def __init__():
        pass

    def init():
        logging.getLogger("requests").setLevel(logging.WARNING)
        burpprocess = start_burp(context)

        # Send a message to headless-scanner-driver extension and wait for response.
        # Communicates to the scanner driver using a magical port number.
        # See https://github.com/F-Secure/headless-scanner-driver for additional documentation

        proxydict = {'http': 'http://' + context.burp_proxy_address,
                     'https': 'https://' + context.burp_proxy_address}
        try:
            requests.get("http://localhost:1111", proxies=proxydict)
        except requests.exceptions.RequestException as e:
            kill_subprocess(burpprocess)
            raise Exception("Could not fetch scan item status over %s (%s). Is the proxy listener on?" %
                           (context.burp_proxy_address, e))
        proxy_message = read_next_json(burpprocess)
        if proxy_message is None:
            kill_subprocess(burpprocess)
            raise Exception( "Timed out communicating to headless-scanner-driver extension over %s. Is something else running there?" % 
                           (context.burp_proxy_address))
	def kill():

        poll = select.poll()
        poll.register(burpprocess.stdout, select.POLLNVAL | select.POLLHUP)  # pylint: disable=E1101
        try:
            requests.get("http://localhost:1112", proxies=proxydict)
        except requests.exceptions.RequestException as e:
            kill_subprocess(burpprocess)
            raise Exception( "Could not fetch scan results over %s (%s)" % 
                           (context.burp_proxy_address, e))
        descriptors = poll.poll(10000)
        if descriptors == []:
            kill_subprocess(burpprocess)
            raise Exception( "Burp Suite clean exit took more than 10 seconds, killed" )
        return True

    
    def finnish(context, timeout):
        #Call to run a test scenario referenced by the scenario identifier
        #scan_start_time = time.time()  # Note the scan start time
    
        # Wait for end of scan or timeout
        re_abandoned = re.compile("^abandoned")  # Regex to match abandoned scan statuses
        re_finished = re.compile("^(abandoned|finished)")  # Regex to match finished scans
        proxydict = {'http': 'http://' + context.burp_proxy_address,
                     'https': 'https://' + context.burp_proxy_address}
        while True:  # Loop until timeout or all scan tasks finished
            # Get scan item status list
            try:
                requests.get("http://localhost:1111", proxies=proxydict, timeout=1)
            except requests.exceptions.ConnectionError as error:
                kill_subprocess(burpprocess)
                raise Exception("Could not communicate with headless-scanner-driver over %s (%s)" %
                               (context.burp_proxy_address, error.reason))
            # Burp extensions' stdout buffers will fill with a lot of results, and
            # it hangs, so we time out here and just proceed with reading the output.
            except requests.Timeout:
                pass
            proxy_message = read_next_json(burpprocess)
            # Go through scan item statuses statuses
            if proxy_message is None:  # Extension did not respond
                kill_subprocess(burpprocess)
                raise Exception("Timed out retrieving scan status information from Burp Suite over %s" % context.burp_proxy_address)
            finished = True
            if proxy_message == []:  # No scan items were started by extension
                kill_subprocess(burpprocess)
                raise Exception("No scan items were started by Burp. Check web test case and suite scope.")
            for status in proxy_message:
                if not re_finished.match(status):
                    finished = False
                if hasattr(context, 'fail_on_abandoned_scans'):  # In some test setups, abandoned scans are failures, and this has been set
                    if re_abandoned.match(status):
                        kill_subprocess(burpprocess)
                        raise Exception("Burp Suite reports an abandoned scan, but you wanted all scans to succeed. DNS problem or non-Target Scope hosts targeted in a test scenario?")
            if finished is True:  # All scan statuses were in state "finished"
                break
            if (time.time() - scan_start_time) > (timeout * 60):
                kill_subprocess(burpprocess)
                raise Exception("Scans did not finish in %s minutes, timed out. Scan statuses were: %s" %
                               (timeout, proxy_message))
            time.sleep(10)  # Poll again in 10 seconds

	def collect():
        # Retrieve scan results and request clean exit
    
        try:
            requests.get("http://localhost:1112", proxies=proxydict, timeout=1)
        except requests.exceptions.ConnectionError as error:
            kill_subprocess(burpprocess)
            raise Exception("Could not communicate with headless-scanner-driver over %s (%s)" %
                           (context.burp_proxy_address, error.reason))
        # Burp extensions' stdout buffers will fill with a lot of results, and
        # it hangs, so we time out here and just proceed with reading the output.
        except requests.Timeout:
            pass
        proxy_message = read_next_json(burpprocess)
        if proxy_message is None:
            kill_subprocess(burpprocess)
            raise Exception("Timed out retrieving scan results from Burp Suite over %s" % context.burp_proxy_address)
        context.results = proxy_message  # Store results for baseline delta checking
    
        # Wait for Burp to exit
    
	def kill():
        poll = select.poll()
        poll.register(burpprocess.stdout, select.POLLNVAL | select.POLLHUP)  # pylint: disable-msg=E1101
        descriptors = poll.poll(10000)
        if descriptors == []:
            kill_subprocess(burpprocess)
            raise Exception("Burp Suite clean exit took more than 10 seconds, killed")

        return True
