from mittn import MittnTlsChecker, Config

c = Config('mittn.conf')

# don't check for preferred or enabled cipher suites
#c.suites_preferred = []

t = MittnTlsChecker(config=c)
checks = t.run('www.google.com')
for c in checks:
    print(c)
    print()
