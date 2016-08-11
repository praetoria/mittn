from mittn import MittnTlsChecker, Config

c = Config('tlschecker','mittn.conf')

t = MittnTlsChecker(config=c)
failed,passed,skipped = t.run('www.f-secure.com')
for c in passed+failed+skipped:
    print(c)
    print()
