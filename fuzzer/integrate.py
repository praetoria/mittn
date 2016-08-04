from mittn.fuzzer import Target, MittnFuzzer, Config
base = 'http://127.0.0.1:8000/'

c = Config("fuzzer")
c.db_url = "sqlite:////tmp/db"
m = MittnFuzzer(config=c)
m.init()

#test json submission
t = Target('valid_json',
           'POST',
           base + 'valid_json',
           'json',
           '{"data":"valid"}')
m.add_target(t)
"""
t = Target('valid_form',
           'POST',
           base + 'valid_form',
           'urlencode',
           'data=valid')
m.add_target(t)
"""

m.fuzz()
