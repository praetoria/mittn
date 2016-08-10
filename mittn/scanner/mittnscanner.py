from mittn.config import Config
from mittn.archiver import Archiver
from mittn.scanner.pythonburp import PythonBurp
from mittn.scanner.scannerissue import ScannerIssue

class MittnScanner(object):
    def __init__(self,archiver=None,burp=None,config=None):
        self.config = config or Config("scanner","mittn.conf")
        db_url = None
        if hasattr(self.config,'db_url'):
            db_url = self.config.db_url
        self.archiver = archiver or Archiver(db_url)
        self.burp = burp or PythonBurp(self.config.burp_cmdline,
                self.config.burp_proxy_address)
        self.results = []
    
    def init(self):
        self.archiver.init(ScannerIssue)

    def run_tests(self,testfunction,tests):
        """ Takes a test function which takes a test name
        as a parameter and a list of test names to feed it.
        """
        try:
            self.burp.start()
            for test in tests:
                if testfunction(test,self.config.burp_proxy_address) != 0:
                    raise RuntimeError("Test '%s' failed to execute" % test)
                self.burp.finish(int(self.config.timeout))
                result = self.burp.collect()
                for r in result:
                    issue = ScannerIssue.issue_from_dict(test,r)
                    self.archiver.add_if_not_found(issue)
                self.results.append(result)
        finally:
            self.burp.kill()

    def collect_results(self):
        return self.results
