# pylint: disable=E0602,E0102

"""
Copyright (c) 2013-2014 F-Secure
See LICENSE for details

Burp and Burp Suite are trademarks of Portswigger, Ltd.
"""

import shlex
import subprocess
import select
import requests
import json
import time
import re
import logging

class PythonBurp():
    def __init__(self,cmdline, proxy_address):
        self.proxydict = {'http': 'http://' + proxy_address,
                         'https': 'https://' + proxy_address}
        self.proxy_address = proxy_address
        self.cmdline = cmdline

    def start(self):
        """Start Burp Suite as subprocess and wait for the extension to be ready."""
        burpcommand = shlex.split(self.cmdline)
        self.process = subprocess.Popen(burpcommand, stdout=subprocess.PIPE)
        # get next json output from the burp process
        proxy_message = self.read_next_json()
        if proxy_message is None:
            self.kill_subprocess()
            raise ValueError("Starting Burp Suite and extension failed or timed out. Is extension output set as stdout? Command line was: %s" % self.cmdline)
        if proxy_message.get("running") != 1:
            self.kill_subprocess()
            raise ValueError("Burp Suite extension responded with an unrecognised JSON message")
        # In some cases, it takes some time for the proxy listener to actually
        # have an open port; I have been unable to pin down a specific time
        # so we just wait a bit.
        time.sleep(5)

        """ Check that the extension is working."""
        logging.getLogger("requests").setLevel(logging.WARNING)

        # Send a message to headless-scanner-driver extension and wait for response.
        # Communicates to the scanner driver using a magical port number.
        # See https://github.com/F-Secure/headless-scanner-driver for additional documentation

        proxydict = self.proxydict
        try:
            requests.get("http://localhost:1111", proxies=proxydict)
        except requests.exceptions.RequestException as e:
            self.kill_subprocess()
            raise Exception("Could not fetch scan item status over %s (%s). Is the proxy listener on?" %
                           (self.proxy_address, e))
        proxy_message = self.read_next_json()
        if proxy_message is None:
            self.kill_subprocess()
            raise Exception( "Timed out communicating to headless-scanner-driver extension over %s. Is something else running there?" % 
                           (self.proxy_address))

    def kill(self):
        """ Kill the burp process """

        poll = select.poll()
        poll.register(self.process.stdout, select.POLLNVAL | select.POLLHUP)  # pylint: disable=E1101
        try:
            requests.get("http://localhost:1112", proxies=self.proxydict)
        except requests.exceptions.RequestException as e:
            self.kill_subprocess()
        descriptors = poll.poll(10000)
        if descriptors == []:
            self.kill_subprocess()
            raise Exception( "Burp Suite clean exit took more than 10 seconds, killed" )
        return True

    
    def finish(self, timeout):
        """ Wait for ongoing scans to finish """

        scan_start_time = time.time()  # Note the scan start time
    
        # Wait for end of scan or timeout
        re_abandoned = re.compile("^abandoned")  # Regex to match abandoned scan statuses
        re_finished = re.compile("^(abandoned|finished)")  # Regex to match finished scans

        while True:  # Loop until timeout or all scan tasks finished
            # Get scan item status list
            try:
                requests.get("http://localhost:1111", proxies=self.proxydict, timeout=1)
            except requests.exceptions.ConnectionError as error:
                self.kill_subprocess()
                raise Exception("Could not communicate with headless-scanner-driver over %s (%s)" %
                               (self.proxy_address, error.reason))
            except requests.Timeout:
                # Burp extensions' stdout buffers will fill with a lot of results, and
                # it hangs, so we time out here and just proceed with reading the output.
                pass
            proxy_message = self.read_next_json()
            # Go through scan item statuses statuses
            if proxy_message is None:  # The extension did not respond
                self.kill_subprocess()
                raise Exception("Timed out retrieving scan status information from Burp Suite over %s" %
                               (self.proxy_address))
            finished = True
            if proxy_message == []:  # No scan items were started by the extension
                #this might happen if  the test that was ran had no injectable input.
                self.kill_subprocess()
                raise Exception("No scan items were started by Burp. Check web test case and suite scope.")
            for status in proxy_message:
                if not re_finished.match(status):
                    finished = False
                # TODO: currently the fail_on_abandoned_scans option is not used at all
                if hasattr(self, 'fail_on_abandoned_scans'):  # In some test setups, abandoned scans are failures, and this has been set
                    if re_abandoned.match(status):
                        self.kill_subprocess()
                        raise Exception("Burp Suite reports an abandoned scan, but you wanted all scans to succeed. DNS problem or non-Target Scope hosts targeted in a test scenario?")
            if finished is True:  # All scan statuses were in state "finished"
                break
            if (time.time() - scan_start_time) > (timeout * 60):
                self.kill_subprocess()
                raise Exception("Scans did not finish in %s minutes, timed out. Scan statuses were: %s" %
                               (timeout, proxy_message))
            time.sleep(10)  # Poll again in 10 seconds

    def collect(self):
        # Retrieve scan results
    
        try:
            requests.get("http://localhost:1113", proxies=self.proxydict, timeout=1)
        except requests.exceptions.ConnectionError as error:
            self.kill_subprocess()
            raise Exception("Could not communicate with headless-scanner-driver over %s (%s)" %
                           (self.proxy_address, error.reason))
        # Burp extensions' stdout buffers will fill with a lot of results, and
        # it hangs, so we time out here and just proceed with reading the output.
        except requests.Timeout:
            pass
        proxy_message = self.read_next_json()
        if proxy_message is None:
            self.kill_subprocess()
            raise Exception("Timed out retrieving scan results from Burp Suite over %s" % self.proxy_address)

        return proxy_message

    def kill_subprocess(self):
        """Kill a subprocess, ignoring errors if it's already exited."""
        try:
            self.process.kill()
        except OSError:
            pass
        return

    def read_next_json(self):
        """Return the next JSON formatted output from Burp Suite as a Python dict object."""
        # We will wait on Burp Suite's standard output
        pollobj = select.poll()
        pollobj.register(self.process.stdout, select.POLLIN)
        jsonobject = None  # Default to a failure
        while True:
            # Wait for max. 30 s, if timeout, return None.
            descriptors = pollobj.poll(30000)
            if descriptors == []:
                break
            # Read a line; if not JSON, continue polling with a new timeout.
            line = self.process.stdout.readline()
            if str(line) == '':  # Burp Suite has exited
                break
            try:
                jsonobject = json.loads(str(line,'utf-8'))
            except ValueError:
                continue
            break
        return jsonobject
