from mittn.fuzzer import Target, MittnFuzzer

m = MittnFuzzer()
m.init()
m.add_target(Target(
	'simple_test',
	'GET',
	'http://127.0.0.1:8000/',
	'urlencoded',
	'id=1337'
))
m.fuzz()
