from mittn import MittnScanner
from mittn.config import Config
from subprocess import call

def testfunction(test,proxy):
	#this will run a unit test or a set of tests through burp.
	#the proxy has been configured in the selenium before_all function
    status = call(
        'python3 -m unittest MySiteTests.MyFeature.%s'%
        (test),
        shell=True)
    # Retrutn True if succeeded, False otherwise. If your test fails,
    # don't expect the security tests to succeed either.
    return status == 0

#a list of tests, units or modules to run
tests = [
        'fancy_feature',
        'fun_functionality',
        ]

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
