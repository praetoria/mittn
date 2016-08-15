=========================
 tlschecker installation
=========================

If you need further guidance
============================

If you stumble upon a bug, please file a ticket on the GitHub
project or send a pull request with the patch.

TLS checker concept
===================

The TLS checker runs the great sslyze.py tool against a server,
requesting XML output. The test steps then interrogate the XML
tree to find out whether the server configuration is correct.

These tests should be run against production deployment.

Software requirements
=====================

1. Python package dependencies; see setup.py.

2. sslyze, which you can obtain from
   https://github.com/nabla-c0d3/sslyze. The version against which
   the tool works is 0.12. If the XML output changes, tests may break
   unexpectedly. You may want to obtain a pre-built version from
   https://github.com/nabla-c0d3/sslyze/releases. Ensure the script
   is executable.

Environment requirements
========================

- The tests are written in Python by using functions imported from
  Mittn. Any printing or outputting of results has to be done by
  you in the script using the results provided by the MittnTlsChecker
  plugin.

- Set up your configuration either using the example mittn.conf in
  github as a template or by setting the options directly in the test
  script.

- The target host and port has to be specified in the test script.
  For assistance on the configuration or options please see the
  example files in the repository.

Setting up the test case
========================

The important files that apply to tlschecker tests are:

  1. The tlschecker example test script is located in
     mittn/examples/ You can use it as a template or to
     just see how the Mittn suite is used.

  2. General test configuration items in
     mittn/examples/mittn.conf; default values for the options
     are commented out.

The tests use an optimisation where the potentially slow scanning
activity is done only once, the result is stored, and subsequent tests
just check the resulting XML.

After doing a connection, you should probably have a "Then" statement
"the connection results are stored".

Subsequent steps that start with "Given a stored connection result"
operate with the result set that was last stored.

Running the tests
=================

Run the tests with

  behave features/yourfeaturefile.feature --junit --junit-directory PATH

with the Mittn directory in your PYTHONPATH (or run the tool from
Mittn/), and PATH pointing where you want the JUnit XML output. If
your test automation system does not use JUnit XML, you can, of
course, leave those options out.

