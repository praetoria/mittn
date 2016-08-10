class ScannerDefaults(object):
    def __init__(self):
        # attributes in the config which are lists
        self.list_attributes = [
                ]
        self.defaults = """
[scanner]
burp_cmdline=java -jar -Xmx1g -Djava.awt.headless=true -XX:MaxPermSize=1G /home/husky/builds/burpsuite/burpsuite_pro_v1.7.04.jar
burp_proxy_address=127.0.0.1:8080
timeout=1
"""
