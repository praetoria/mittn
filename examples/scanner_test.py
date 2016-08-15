from mittn import MittnScanner
from mittn import Archiver
from subprocess import call

def testfunction(test,proxy):
    status = call(('curl http://localhost:9000/%s?input=aoeu' +
        ' --proxy http://%s 1>/dev/null 2>/dev/null') % (test,proxy),
            shell=True)
    # True if succeeded, False otherwise
    return status == 0

tests = [
        'xss1',
        'xss2',
        ]

# creating a config object is optional
# if it is not created a default config
# will be created and mittn.conf will
# be read from the current directory
c = Config('scanner')

# burp proxy address
c.proxy_address = '127.0.0.1:8080'

# timeout in minutes for the tests
c.timeout = '1'

# creating the archiver is also optional
# but if it is not created db_url has to
# be specified in the config file or object
a = Archiver('sqlite:////tmp/db')

scanner = MittnScanner(archiver=a,config=c)

# initialize the database
scanner.init()
scanner.run_tests(testfunction,tests)
results = scanner.collect_results()

# unless there are any findings results
# are an empty list
for r in results:
    print(r)
