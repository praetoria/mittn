from mittn import MittnScanner
from mittn.config import Config
from subprocess import call


#Define a callback function to run a single, named test scenario.
#The adress of the intercepting proxy that is the scanner is provided.
#This function will be called for every test that is to be run through
#the mittn scanner. These fould be functional test scenarios or unit
#tests that make requests.
def testfunction(test,proxy):
    #In this example the test is a single curl command tto get a resource.
    status = call(
        'curl http://localhost:8000/%s --proxy http://%s 1>/dev/null 2>/dev/null'%
        (test,proxy),
        shell=True)
    # Retrutn True if succeeded, False otherwise. If your test fails,
    # don't expect the security tests to succeed either.
    return status == 0

#Define a lit of test scenarios that will be run. These would probably be
#names of single test scenarios as defined in your test framework.
tests = [
        'fancy_feature',
        'fun_functionality',
        ]

#The default configurations are fine, so we'll just go with those. The path
#to the burp jar is the only one we need to set. One you get a feeling for
#mittn, feel free to edit the mittn.conf file.
c = Config('scanner', None);
c.path = '/home/kiveju2/burp/burpsuite_pro_v1.7.04.jar'
scanner = MittnScanner(config = c)
scanner.init()

#Run all tests one by one, and store the scanner fingings in the database.
scanner.run_tests(testfunction,tests)

#Write a simple report and exit with 0 if no new issues were found.
new_issues = len(scanner.get_results())
print("{} new isses found.".format(new_issues))
exit(new_issues)
