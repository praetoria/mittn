from mittn.config import Config
from mittn.archiver import Archiver
from mittn.scanner.pythonburp import PythonBurp

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
    
    def run_tests(self,testfunction,tests):
        """ Takes a test function which takes a test name
        as a parameter and a list of test names to feed it.
        """
        # TODO: This is just a preliminary draft.
        self.burp.start()
        for test in tests:
            if testfunction(test) != 0:
                raise RuntimeError("Test '%s' failed to execute" % test)
            self.burp.finish(int(self.config.timeout))
            result = self.burp.collect()
            self.results.append(result)
        self.burp.kill()

    def collect_results(self):
        # TODO: Return a count of new findings etc
        return len(self.results)
