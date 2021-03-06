class TlsDefaults(object):
    """
    Remember to add the name of a new list attribute
    you want to add in the list_attributes list,
    to make sure it gets parsed correctly
    """
    def __init__(self):
        # attributes in the config which are lists
        self.list_attributes = [
                "suites_blacklisted",
                "suites_enabled",
                "suites_preferred",
                "protocols_disabled",
                "protocols_enabled",
                ]
        self.defaults = """
[tlschecker]

protocols_enabled = TLSv1_2

protocols_disabled = SSLv2,SSLv3

suites_preferred=
    DHE.*GCM,DHE*AES256,
    ECDHE.*GCM,ECDHE.*AES256

suites_enabled=
    DHE-,ECDHE-

suites_blacklisted=
    EXP-,ADH,AECDH,
    NULL,DES-CBC-,RC2,
    RC5,MD5,CAMELLIA,
    SEED,IDEA,SRP-,
    PSK-,DSS,ECDSA,
    DES-CBC3,RC4

days_valid=30

dh_group_size=2048

public_key_size=2048

sslyze_path=/usr/bin/sslyze
        """
