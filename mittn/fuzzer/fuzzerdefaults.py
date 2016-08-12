class FuzzerDefaults(object):
    def __init__(self):
        # attributes in the config which are lists
        self.list_attributes = [
                "methods",
                "allowed_status_codes",
                "disallowed_status_codes",
                "body_errors",
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
body_errors=string,server error,
    invalid response, bad gateway,
    internal ASP error, service unavailable,
    exceeded, premature, fatal error,
    proxy error, database error,
    backend error, mysql, root:,
    parse error,exhausted,
    warning, denied
"""
