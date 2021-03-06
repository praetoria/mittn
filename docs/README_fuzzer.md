===================================
HTTP Injector / Fuzzer Installation
===================================

If you have a question, please open a ticket at
https://github.com/F-Secure/mittn/issues?labels=question and tag it
with the 'question' label.

If you stumble upon a bug, please file a ticket on the GitHub
project or send a pull request with the patch.

HTTP Injector / Fuzzer Concept
==============================

The HTTP Injector / Fuzzer takes an HTTP API (url parameters, form
submissions or JSON submissions) and injects malformed input to each
of the values and parameters in the submission. The malformed input
can come from a library of static, hand-crafted inputs, or from a
fuzzer (currently, generated using Radamsa from the University of
Oulu, Finland). When using the fuzzer, the malformed inputs are
created based on valid examples you provide.

Servers that fail to process malformed inputs may exhibit a range of
responses:

- A 5xx series error, indicating a server-side error
- A timeout
- A response that contains a string that usually indicates an error
  situation (e.g., "internal server error")
- An HTTP level protocol error

The test tool can look for these kinds of malformed responses. If one
is encountered, the test case that caused the response is logged in a
database. A developer can look at the database entries in order to
reproduce and fix the issue.

These responses do not necessarily mean that the system would be
vulnerable. However, they most likely indicate a bug in input
processing, and the code around the injection path that triggered the
problem is probably worth a closer look.

The system does _not_ look for malformed data that would be reflected
back in the responses. This is a strategy often used for Cross-Site
Scripting detection. Please look at dedicated web vulnerability
scanners such as Burp Suite Professional or OWASP Zaproxy if you
require this (and the associated Mittn test runner for headless
scanning). The system also does not do a very deep SQL injection
detection. For this, we suggest using tools such as SQLmap.

The test system runs test cases described in short python scripts.
The interface is designed to makes it easy to create new tests for new HTTP
APIs with little programming experience.

The test system also supports "valid case instrumentation", where each
malformed submission is interleaved with a valid case. The valid case
needs to succeed. Valid case instrumentation is used for:

- Re-authenticating and authorising the test script to the target
  system, if the malformed test case caused the authorisation to
  expire.
- Detecting cases where a valid request following an invalid request
  is not properly processed. This may indicate a Denial of Service
  issue.

Quickstart
==========

1. Install the mittn package.
2. Create a test script (examples are that you can edit are
   available in the repository).
3. Check the necessary `radamsa_path` configuration.
4. Run the  script:

     python your_test_script.py

For details, read on.

Software requirements
=====================

1. Python3, the development was done with 3.4 and 3.5, so older
   versions are not guaratneed to work.

2. Radamsa, a fuzzer compiled on your system. Radamsa is available
   from https://github.com/aoh/radamsa. Mittn has been
   tested with version 0.5. Radamsa is an excellent file-based fuzzer
   created by the University of Oulu Secure Programming Group.

Environment requirements
========================

- New findings are added into an SQL database, which holds the
  information about known false positives, so that they are not
  reported during subsequent runs. You need to have CREATE TABLE,
  SELECT and INSERT permissions on the database.

- You need a deployment of your test system that is safe to test
  against. You might not want to use your production system due to
  Denial of Service potential. You might not want to run the tool
  through an Intrusion Detection System or a Web Application Firewall,
  unless you want to test the efficacy and behaviour of those
  solutions.

- You may not want to run the fuzz tests from a host that is running
  antivirus software. Fuzz test cases created by the fuzzer are
  written to files and have a tendency of being mistaken as
  malware. These are false positives. There is no real malware in the
  tool, unless you provide it with such inputs.

Configuration
=============

The behaviour of mittn can be configured with configuration files,
but most of the default configurations should be ok to start off
with. The configurable settings are documented in the example
configuration file.

What are baseline databases?
============================

The tests in Mittn have a tendency of finding false positives. Also,
due to the distributed nature of cloud-based Continuous Integration
systems, the tests might be running on transient nodes that are
deployed just for the duration of a test run and then shut down. The
baseline database holds the information on new findings and known
false positives in a central place.

Currently, the httpfuzzer and headlessscanner tools use baseline
databases. The headlessscanner tool requires a database; the httpfuzzer
can be run without one, but the usefulness is greatly reduced.

The tool uses SQL Alchemy Core as a database abstraction layer. The
supported database options are listed at
http://docs.sqlalchemy.org/en/rel_0_9/dialects/index.html.

If you need a centralised database that receives issues from a number
of nodes, you need a database with network connectivity.  If you only
need a local database, you can use a file-based (such as sqlite)
database. The latter is much easier to set up as it requires no
database server or users to be defined, this is the default behaviour.

Whichever database you use, you will provide the configuration options
in mittn.conf or the test script as a database URI. For details on the
URI syntax, see
http://docs.sqlalchemy.org/en/rel_0_9/core/engines.html#database-urls.

Managing findings
=================

After a failing test run, the database (if one is used) will contain
new findings. They will be marked as new. Once the issue has been
studied, the developers should:

1) If the issue was a real finding, remove the issue from the
   database. If the issue re-occurs, it will fail the test again.

2) If the issue was a false positive, mark it as not new by zeroing
   the new_issue flag. if the issue re-occurs, it will not be reported
   again but treated as a false positive.

Selecting the appropriate database
==================================

The test system uses an SQL database to store false positives, so that
it doesn't report them as errors. Whenever new positives are
encountered, those are added to the database. The developers can then
check the finding. If the finding is a false positive, they will need
to mark it as such in the database (by setting a flag new_issue as
false (or zero) on that finding). If it was a real positive, that
finding needs to be removed from the database, and of course, the
system under test needs a fix.

The system supports either databases in local files with sqlite, or a
connection over the network to an off-host database. Select
the database solution you want to use:

  1. If you run the tests on a developer machine, or on a host that is
     not redeployed from scratch every time (i.e., the host has
     persistent storage), or if the host has a persistent
     network-mounted file system, it is probably easier to store the
     results into a file-based local database.

  2. If you run tests concurrently on several nodes against the same
     system under test, or if your test system is on a VM instance
     that is destroyed after the tests (i.e., the host has no
     persistent storage), or if you want to share the results easily
     with a larger team, it is probably easier to use a
     network-connected database.

Setup instructions
==================

User-editable files
-------------------

Once you have installed the mittn package. Test cases are written
in simple python scripts. There are templates for writing them in
the examples directory in the repository.

For ease of configuration you may use a configuration file, mittn.conf,
an example file with defaults commented out is located in the examples
directory as well.

Authentication and authorisation
--------------------------------

If you do NOT need to authorise yourself to your test target,
everything is okay.

If your system DOES require authorisation, then we have a problem.
This feature is not implemented yet, so raise a Git Hub Issue if
you need this.

In the future it will be handled as follows.  In essence, you
need to return a Requests library Auth object that implements
the authentication and authorisation against your test target. The
Requests library already provides some standard Auth object types. If
your system requires a non-standard login (e.g., username and
password typed into a web form), you need to provide the code to
perform this. Please see the Requests library documentation at
http://docs.python-requests.org/en/latest/user/authentication/
and the template for modification instructions.

Environment settings
--------------------

- Edit your mittn.conf to reflect your setup. You need to edit
  at least the common and httpfuzzer specific settings. There
  is a template available in mittn/examples/mittn.conf that
  you can copy and edit. It is not compulsory but if you decide to
  use multiple tools you should use a config file.

- Edit mittn.conf so that context.dburl points to
  your database. The pointer is an SQL Alchemy URI, and the syntax
  varies for each database. An example is provided in the file for
  sqlite. Further documentation on the database URIs is available on
  http://docs.sqlalchemy.org/en/rel_0_9/core/engines.html#database-urls.

- Ensure that you have CREATE TABLE, INSERT and SELECT rights to the
  database. (SQL Alchemy might require something else under the hood
  too, depending on what database you are using.)

- During the first run of the tool, the false positives database table
  will be automatically created. If one exists already, it will not be
  deleted.

Writing test cases
==================

Test cases are defined by Targets. These are objects that have the
necessary information to generate, send and verify fuzzed cases.
You can find example tests in the `examples/scanner_example.py`
file. The Target class is quite simple and all the testable targets
could be generated in pyhton from an API definition language or
documentation, or read from files.

Defining test targets
---------------------

	scenario_id

You should give each test case a different ID (an arbitrary string)
as that helps you to separate results.

	method

The method used to send the valid request.

	uri

The URI of the resource being targeted.

	submission_type

The type of the submission, this is used to figure out POST data
encodings and the Content-Type header. Currently it dould be one of
`"urlencode"`, `"json"`, or `"url-parameters"`.

	valid_submission

A valid submission for this URI. This could be
someting like `'{"foo": 42, "bar": "Kauppuri 5"}'`, or
`'foo=42&bar=Kauppuri%205'`.


Fuzzer configuration
--------------------

	methods=GET,POST,PUT,DELETE

What HTTP methods should be used to inject. Even if your system only
expects, say, POST, it might be a good idea to try injecting with GET,
too.

	timeout=5

How long to wait for a server response before marking it as an issue.

	allowed_status_codes=200-299,400-499

The status codes in the responses that signal of the service being healthy and not in a bad state.

	disallowed_status_codes=500-599

Status codes that will cause the test to create a new issue. The
`allowed_status_codes` has precedence, so this setting is only used
if the allowed codes is empty.

	anomalies=20

How many anomalies to generate per injectable point. When fuzzing,
you can start small but you should probably aim to run hundreds
or thousands of test cases when you actually take the system into
production.

You should pick this based on how fast you need the tests to
run. Running mittn with 20 anomalies five timmes is the same as
running it once with a hundred, since the anomalies are always
generated from scratch.

	body_errors

These strings check for anomalous server responses. The response bodies
are searched for the specified strings. If you know your framework's
default critical error strings, you should probably add them here, and
remove any that are likely to cause false positives.

Examples of strings would be those found in stacktraces, SQL errors,
and technology-specific errors.

Setting up valid case instrumentation
-------------------------------------
TODO
  Given valid case instrumentation with success defined as "100-499"

Valid case instrumentation tries a valid test case after each
injection. This is done for two reasons:

  1) If you need authentication / authorisation, the valid case tests
     whether your auth credentials are still valid, and if not, it
     logs you in again.
  2) If the valid case suddenly stops working, the remaining injection
     cases wouldn't probably actually test your system either.

A valid case is the same API call which you are using injection
against.

If you do not use valid case instrumentation, the valid case is tried
just once as the first test case.

Valid cases have an HTTP header that indicates they are valid
cases. This may be helpful if you are looking at the injected requests
using a proxy tool.


Findings in the database
------------------------

The findings in the database contain the following columns:

  new_issue: A flag that indicates a new finding. If this is 0, and
  the issue is found again, it will not be reported - it will be
  assumed to be a known false positive.

  issue_no: A unique serial number.

  timestamp: The timestamp (in UTC) when the request was sent to the
  server. You can use this information to correlate findings in server
  logs.

  test_runner_host: the IP address from where the tests were run. You
  can use this to correlate the finding against server logs. If you
  only see local addresses here, have a look at your /etc/hosts file.

  scenario_id: The arbitrary scenario identifier you provided in the
  feature file.

  url: The target URL that was being injected.

  server_protocol_error: If the issue was caused by a malformed HTTP
  response, this is what the Requests library had to say about the
  response.

  server_timeout: True if the request timed out.

  server_error_text_match: True if the server's response body matched
  one of the error strings listed in the feature file.

  req_method: The HTTP request method (e.g., POST) used for the injection.

  req_headers: A JSON structure of the HTTP request headers used for
  the injection.

  req_body: The HTTP request body that was injected. (This is where
  you can find the bad data.)

  resp_statuscode: The HTTP response status code from the server.

  resp_headers: A JSON structure of the HTTP response headers from the
  server.

  resp_body: The body of the HTTP response from the server.

  resp_history: If the response came after a series of redirects, this
  contains the requests and responses of the redirects.

Future features
---------------

