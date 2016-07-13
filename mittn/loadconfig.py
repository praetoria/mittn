from configparser import ConfigParser

class LoadConfig:
    def __init__(self,section):
        config = ConfigParser()
        config.read("mittn.conf")
        # general configuration
        for key in config["mittn"]:
            setattr(self,key,config["mittn"][key])
        # tool based configuration
        for key in config[section]:
            setattr(self,key,config[section][key])

        # parse list type attributes
        for attr in [
                "suite_blacklist",
                "suite_whitelist",
                "preferred_suites",
                "injection_methods"
                ]:
            if hasattr(self, attr):
                l = getattr(self,attr).strip(",").split(",")
                l = [i.strip() for i in l]
                setattr(self,attr,l)
