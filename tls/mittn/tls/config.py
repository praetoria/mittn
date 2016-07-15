from configparser import ConfigParser

class Config:
    def __init__(self,path=None,sslyze_path=None,protocols=None):

        ## default configuration for tlschecker ##

        self.protocols = protocols or \
            {"SSLv2": False,"SSLv3": False,"TLSv1_2": True}

        self.suites_preferred = [
                "DHE.*GCM", "DHE.*AES256",
                "ECDHE.*GCM","ECDHE.*AES256",
                ]

        self.suites_disabled = [
                "EXP-","ADH","AECDH",
                "NULL","DES-CBC-","RC2",
                "RC5","MD5","CAMELLIA",
                "SEED","IDEA","SRP-",
                "PSK-","DSS","ECDSA",
                "DES-CBC3","RC4",
                ]

        self.suites_enabled = [
                "DHE-","ECDHE-",
                ]

        # cert valid for at least this long from today
        self.days_valid = 30
        self.dh_group_size = 2048
        self.public_key_size = 2048
        self.path = path
        self.sslyze_path = sslyze_path or "/usr/bin/sslyze"

        ## file based configuration ##
        config = ConfigParser()
        config.read(path)

        # comma separated list type attributes in config file
        list_attributes = [
            "suites_disabled",
            "suites_enabled",
            "suites_preferred",
        ]
        for section in ['mittn','tlschecker']:
            if section in config:
                for key in config[section]:
                    s = config[section][key]
                    # parse comma separated lists
                    if key in list_attributes:
                        s = s.strip(",").split(",")
                        s = [i.strip() for i in s]
                    setattr(self,key,s)
