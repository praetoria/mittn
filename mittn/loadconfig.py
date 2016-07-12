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
