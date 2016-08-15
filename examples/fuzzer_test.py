from mittn import Target, MittnFuzzer, Archiver, Config

c = Config('fuzzer','mittn.conf')
c.radamsa_path='/usr/bin/radamsa'

a = Archiver("sqlite:////tmp/db")

m = MittnFuzzer(archiver=a,config=c)

# initialized the database
m.init()
t = Target('simple_test',
           'GET',
           'http://127.0.0.1:9000/xss1',
           'urlparams',
           'input=1337')
m.add_target(t)

m.fuzz()
