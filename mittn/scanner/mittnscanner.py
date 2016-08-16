from mittn.config import Config
from mittn.archiver import Archiver
from mittn.scanner.pythonburp import PythonBurp
from mittn.scanner.scannerissue import ScannerIssue

class MittnScanner(object):
    def __init__(self,archiver=None,scanner=None,config=None):
        self.config = config or Config("scanner", None)
        db_url = None
        if hasattr(self.config,'db_url'):
            db_url = self.config.db_url
        self.archiver = archiver or Archiver(db_url)
        self.scanner = scanner or PythonBurp(self.config.cmdline +
                " " + self.config.path,
                self.config.proxy_address)
        self.results = []
    
    def init(self):
        self.archiver.init(ScannerIssue)

    def run_tests(self,testfunction,tests):
        """ Takes a test function which takes a test name
        as a parameter and a list of test names to feed it.
        """
        try:
            print('Setting up proxy and scanner...')
            self.scanner.start()
            print('Running tests...')
            for test in tests:
                print(test)
                if not testfunction(test,self.config.proxy_address):
                    raise RuntimeError(
                        "Valid test scenario '%s' failed to execute, using proxy %s"
                        % (test, self.config.proxy_address))
                self.scanner.finish(int(self.config.timeout))
                result = self.scanner.collect()
                for r in result:
                    issue = ScannerIssue.issue_from_dict(test,r)
                    self.archiver.add_if_not_found(issue)
                    self.results.append(r)
        finally:
            self.scanner.kill()

    def get_results(self):
        return self.results
