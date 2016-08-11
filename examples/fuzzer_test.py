from mittn import Target, MittnFuzzer, Archiver

a = Archiver("sqlite:////tmp/db")
m = MittnFuzzer(archiver=a)
m.init()
t = Target('simple_test',
           'GET',
           'http://127.0.0.1:8000/',
           'urlparams',
           'id=1337')
m.add_target(t)

m.fuzz()