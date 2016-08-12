class FuzzerDefaults(object):
    def __init__(self):
        # attributes in the config which are lists
        self.list_attributes = [
                "methods",
                "allowed_status_codes",
                "disallowed_status_codes",
                ]
        self.defaults = """
[fuzzer]
methods=GET,POST
radamsa_path=/usr/bin/radamsa
timeout=30
allowed_status_codes=
    200,404
disallowed_status_codes=
anomalies=1
"""
