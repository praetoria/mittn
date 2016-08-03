from mittn.fuzzer import Target, MittnFuzzer, Config

c = Config("fuzzer")
c.db_url = "./db"
m = MittnFuzzer(config=c)
m.init()
t = Target('simple_test',
           'GET',
           'http://127.0.0.1:8000/',
           'urlparams',
           'id=1337')
m.add_target(t)

m.fuzz()
