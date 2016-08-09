from mittn import MittnScanner
from mittn import Archiver
from subprocess import call

def testfunction(test):
    s = call('curl http://localhost:8000/%s 1>/dev/null 2>/dev/null' % test,
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
