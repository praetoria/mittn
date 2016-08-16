class ScannerDefaults(object):
    def __init__(self):
        # attributes in the config which are lists
        self.list_attributes = [
                ]
        self.defaults = """
[scanner]
db_url=sqlite:////tmp/mittn_scanner_issues.db
cmdline=java -jar -Xmx1g -Djava.awt.headless=true
proxy_address=127.0.0.1:8080
timeout=1
"""
