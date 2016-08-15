from mittn import MittnScanner
from mittn import Archiver
from subprocess import call

#Make a list of test names/scenarios. These would correspond to unit
#test that can be ran from eg. with a commandline test runner. This
#list would preferably be generated from the actual tests.
tests = [
        'xss1',
        'xss2',
        ]

#Define a test function which will be called for every test scenario.
#In this example we are simply making requests to some urls using curl.
#Most tools should have a way to call single tests from the commandline
#by name. If there isn't, then you can simply run all the tests at once,
#but this might make the causes of findings harder to backtrack.
def testfunction(test,proxy):
    status = call(('curl http://localhost:9000/%s?input=aoeu' +
        ' --proxy http://%s 1>/dev/null 2>/dev/null') % (test,proxy),
            shell=True)
    # Retrutn True if succeeded, False otherwise. If your test fails,
	# don't expect the security tests to succeed either.
    return status == 0


#The scanner needs an archiver object that will handle storing the
#findings in a database. The URL format is described in the sqlalchemy
#documentation:
#http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls
a = Archiver('sqlite:////tmp/db')
#Constructm, initialize and run the scanner.
scanner = MittnScanner(archiver=a)
scanner.init()
scanner.run_tests(testfunction,tests)

#Finally dump all the findings (if you want to, they will be in the 
#database in any case). You might want to fail the run of mittn if there
#are new findings in the database.
results = scanner.collect_results()
for r in results:
    print(r)
