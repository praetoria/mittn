from mittn.httpfuzzer.steps import httpfuzzer
m = httpfuzzer()
m.context.scenario_id = 'valid_1'
m.add_target('http://127.0.0.1:8000/valid', 'POST','{"data":"valid"}', 'json')
m.fuzz()
m.context.scenario_id = 'valid_2'
m.add_target('http://127.0.0.1:8000/valid', 'POST','{"data":"valid"}', 'json')
m.fuzz()
