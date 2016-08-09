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
        burp = burp or PythonBurp(self.config.burp_cmdline)
