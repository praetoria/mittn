class Checker(object):

    BODY_ERROR_LIST = [
        'string',
        'server error',
        # 'exception', # too generic!
        'invalid response',
        'bad gateway',
        'internal ASP error',
        'service unavailable',
        'exceeded',
        'premature',
        'fatal error',
        'proxy error',
        'database error',
        'backend error',
        'mysql',
        'root:',
        'parse error',
        'exhausted',
        'warning',
        'denied',
        # 'failure',  # too generic!
    ]

    def check(self, resp_or_exc, body_errors=None, allowed_status_codes=None, disallowed_status_codes=None):
        if isinstance(resp_or_exc, RequestException):
            return True
        elif isinstance(resp_or_exc, Response):
            if (
                allowed_status_codes and resp_or_exc.status_code not in allowed_status_codes or
                disallowed_status_codes and resp_or_exc.status_code in disallowed_status_codes
            ):
                return True
            elif body_errors:
                matches = [index for index, el in enumerate(body_errors) if re.search(el, resp_or_exc.text, re.IGNORECASE)]
                if matches:
                    resp_or_exc.server_error_text_matched = ', '.join([body_errors[m] for m in matches])  # Hacky
                    return True
        else:
            raise NotImplemented

        return False

    # As context manager?
    # with checker() as r:
    #     r.resp = requests.get(...)