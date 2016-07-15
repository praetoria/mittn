from mittn import MittnTlsChecker, Config

c = Config('mittn.conf')

# don't check for preferred or enabled cipher suites
c.suites_preferred = []
c.suites_enabled = []

t = MittnTlsChecker(config=c)
t.run('www.google.com')
