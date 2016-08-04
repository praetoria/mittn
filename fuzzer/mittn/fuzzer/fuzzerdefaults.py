class FuzzerDefaultConfig(object):
    def __init__(self):
        # attributes in the config which are lists
        self.list_attributes = [
                "methods",
                ]
        self.defaults = """
[fuzzer]
methods=GET,POST
radamsa_path=/usr/bin/radamsa
timeout=30
        """
