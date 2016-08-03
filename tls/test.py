from mittn import MittnTlsChecker, Config

c = Config('tlschecker','mittn.conf')

# don't check for preferred or enabled cipher suites
c.suites_preferred = []

t = MittnTlsChecker(config=c)
passed,failed,skipped = t.run('www.google.com')
for c in passed+failed+skipped:
    print(c)
    print()
