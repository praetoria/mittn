from mittn.httpfuzzer import httpfuzzer

mittn = mittn.httpfuzzer(proxy="localhost:8080")
for url, valid_json in components:
    mittn.run(url,valid_json)
