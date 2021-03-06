from configparser import ConfigParser
import io


class Config(object):
    tools = {}
    def __init__(self,tool,path=None):
        ## file based configuration ##
        config = ConfigParser()
        default_config = io.StringIO(Config.tools[tool].defaults)
        config.readfp(default_config)
        if path:
            config.read(path)

        # comma separated list type attributes in config file
        list_attributes = Config.tools[tool].list_attributes

        ## config file based configuration ##
        if not config:
            return
        for section in ['mittn',tool]:
            if section in config:
                for key in config[section]:
                    s = config[section][key]
                    # parse comma separated lists
                    if key in list_attributes:
                        s = s.strip(",").split(",")
                        s = [i.strip() for i in s]
                    setattr(self,key,s)
