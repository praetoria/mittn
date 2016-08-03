from urllib import parse
from collections import OrderedDict

import six


def urlparams_to_dict(params, delimiter=';'):
    """Like urllib.parse_qs() but array values are delimited by colons."""
    paramdict = OrderedDict()
    for keyword_value_pair in params.split(delimiter):
        keyword, values = keyword_value_pair.split('=')
        paramdict[keyword] = []
        for value in values.split(','):
            paramdict[keyword].append(value)
    return paramdict


def dict_to_urlparams(paramdict, delimiter=';'):
    """Like urllib.urlencode() but array values are delimited by colons.

    {'eka': [1, 2, 3], 'toka': ['auto', None, 66]}
    --> eka=1,2,3;toka=auto,,66

    """
    params = []
    for key, value in six.iteritems(paramdict):
        values = []
        for v in value:
            if v is None:  # As a result of injection
                values.append('')
            else:
                values.append(parse.quote_plus(str(v)))
        params.append(parse.quote_plus(key) + '=' + ','.join(values))
    return delimiter.join(params)

def serialise_to_url(dictionary, encode=True):
    """Take a dictionary and URL-encode it for HTTP submission
    :param dictionary: A dictionary to be serialised
    :param encode: Should it be URL-encoded?
    """
    serialised = []
    for key in dictionary.keys():
        if isinstance(dictionary[key], list):  # Multiple values for a key
            for value in dictionary[key]:
                if encode is True:
                    enc_key = parse.quote(str(key))
                    enc_value = parse.quote(str(value))
                    serialised.append("%s=%s" % (enc_key, enc_value))
                else:  # Output raw data (against spec, for fuzzing)
                    serialised.append("%s=%s" % (str(key), str(value)))
        else:
            if encode is True:
                enc_key = parse.quote(str(key))
                enc_value = parse.quote(str(dictionary[key]))
                serialised.append("%s=%s" % (enc_key, enc_value))
            else:  # Output raw data (against spec, for fuzzing)
                serialised.append("%s=%s" % (str(key), str(dictionary[key])))
    return str("&".join(serialised))

