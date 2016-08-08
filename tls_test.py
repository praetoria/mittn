from mittn import MittnTlsChecker, Config

c = Config('tlschecker','mittn.conf')

t = MittnTlsChecker(config=c)
passed,failed,skipped = t.run('www.f-secure.com')
#passed,failed,skipped = t.run('94-237-32-148.fi-hel1.host.upcloud.com',443)
for c in passed+failed+skipped:
    print(c)
    print()
