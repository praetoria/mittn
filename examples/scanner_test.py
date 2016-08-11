from mittn import MittnScanner
from mittn import Archiver
from subprocess import call

def testfunction(test,proxy):
    s = call('curl http://localhost:9000/%s?input=aoeu' +
        ' --proxy http://%s 1>/dev/null 2>/dev/null' % (test,proxy),
            shell=True)
    # TODO: change this into exception
    return s

tests = [
        'xss1',
        'xss2',
        ]

a = Archiver('sqlite:////tmp/db')
scanner = MittnScanner(archiver=a)
scanner.init() # initialize db
scanner.run_tests(testfunction,tests)
results = scanner.collect_results()
for r in results:
    print(r)
