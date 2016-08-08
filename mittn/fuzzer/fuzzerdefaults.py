class FuzzerDefaults(object):
    def __init__(self):
        # attributes in the config which are lists
        self.list_attributes = [
                "methods",
                "allowed_statuses",
                "disallowed_statuses",
                ]
        self.defaults = """
[fuzzer]
methods=GET,POST
radamsa_path=/usr/bin/radamsa
timeout=30
allowed_statuses=
    200,404
disallowed_statuses=
anomalies=1
"""
