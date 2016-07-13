from mittn.httpfuzzer.steps import httpfuzzer
m = httpfuzzer()
m.context.scenario_id = '1'
m.add_valid_json_case('http://127.0.0.1:8000/valid', '{"data":"valid"}', 'POST')
m.fuzz()
