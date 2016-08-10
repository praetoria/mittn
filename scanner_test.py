from mittn import MittnScanner
from mittn import Archiver
from subprocess import call

def testfunction(test,proxy):
    s = call('curl http://localhost:8000/%s --proxy http://%s 1>/dev/null 2>/dev/null' % (test,proxy),
            shell=True)
    return s

tests = [
        'test1',
        'test2',
        'test3',
        ]

a = Archiver('sqlite3:////tmp/db')
scanner = MittnScanner(archiver=a)
scanner.run_tests(testfunction,tests)
results = scanner.collect_results()
