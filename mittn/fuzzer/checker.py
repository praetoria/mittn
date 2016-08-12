from requests import RequestException
from requests.models import Response

class Checker(object):

    def __init__(self, allowed_codes, disallowed_codes, body_errors):
        self.allowed_status_codes    = unpack_rangeparts(allowed_codes   )
        self.disallowed_status_codes = unpack_rangeparts(disallowed_codes)
        self.body_errors = body_errors

    def check(self, resp_or_exc):
        """
        Check wether the server responded with something that indicated an
        error in the server.
        """
        if isinstance(resp_or_exc, RequestException):
            return True
        elif isinstance(resp_or_exc, Response):
            if (
                self.allowed_status_codes and
                resp_or_exc.status_code not in self.allowed_status_codes
                or
                self.disallowed_status_codes and
                resp_or_exc.status_code in self.disallowed_status_codes
            ):
                return True
            elif self.body_errors:
                matches = [index for index, el in enumerate(self.body_errors) if re.search(el, resp_or_exc.text, re.IGNORECASE)]
                if matches:
                    resp_or_exc.server_error_text_matched = ', '.join([self.body_errors[m] for m in matches])  # Hacky
                    return True
        else:
            raise NotImplementedError

        return False

def unpack_rangeparts(rangeparts):
    """Input an integer range spec like ["200","205-207"] and return a list of
    integers like [200, 205, 206, 207]
    :param integerrange: The range specification as a list of strings
    :return: Sorted integers in a list
    """
    if rangeparts == None:
        return None

    integers = []  # To hold the eventual result
    for rangepart in rangeparts:
        rangepart.replace(" ", "")
        rangemaxmin = rangepart.split('-')  # Range is defined with a hyphen
        if len(rangemaxmin) == 1:  # This was a single value
            try:
                integers.extend([int(rangemaxmin[0])])
            except ValueError:
                 raise Exception("Number range %s in the feature file is " \
                    "invalid. Must be integers separated with commas and " \
                    "hyphens" % integerrange)
        elif len(rangemaxmin) == 2:  # It was a range of values
            try:
                rangemin = int(rangemaxmin[0])
                rangemax = int(rangemaxmin[1]) + 1
            except ValueError:
                raise Exception("Number range %s in the feature file is " \
                    "invalid. Must be integers separated with commas and " \
                    "hyphens" % integerrange)
            if rangemin >= rangemax:
                raise Exception("Number range %s in the feature file is " \
                              "invalid. Range minimum is more than " \
                              "maximum" % integerrange)
            integers.extend(range(rangemin, rangemax))
        else:  # Range specifier was not of the form x-y
            raise Exception("Number range %s in the feature file is invalid."\
                          " Incorrect range specifier" % \
                          integerrange)
    return sorted(integers)
