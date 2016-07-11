from configparser import ConfigParser

def LoadConfig(section):
    context = {}
    config = ConfigParser()
    config.read("mittn.conf")
    # general configuration
    for key in config["mittn"]:
            context[key] = config["mittn"][key]
    # tool based configuration
    for key in config[section]:
            context[key] = config[section][key]
    return context
