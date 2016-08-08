from sqlalchemy import Column, types
from sqlalchemy.ext.declarative.api import declarative_base
import datetime

from requests.exceptions import RequestException
from requests.models import Response
from mittn.issue import Issue

import json

class FuzzerIssue(Issue):
    __tablename__ = 'httpfuzzer_issues'

    # We use LargeBinary to store those fields that could contain somehow
    # bad Unicode, just in case some component downstream tries to parse
    # a string provided as Unicode.
     
    # XXX fields that are used in all tools come from issue.py

    server_protocol_error = Column(types.String, default='')
    server_timeout = Column(types.Boolean, default=False, nullable=False)
    server_error_text_detected = Column(types.Boolean, default=False, nullable=False)
    server_error_text_matched = Column(types.String, default='')

    req_method = Column(types.String, default='')
    req_headers = Column(types.LargeBinary, default=b'')
    req_body = Column(types.LargeBinary, default=b'')

    resp_statuscode = Column(types.String, default='')
    resp_headers = Column(types.LargeBinary, default=b'')
    resp_body = Column(types.LargeBinary, default=b'')
    resp_history = Column(types.LargeBinary, default=b'')

    def known_false_positive(self,session):
        # XXX: Because each fuzz case is likely to be separate, we cannot store
        # all those. Two different fuzz cases that elicit a similar response are
        # indistinguishable in this regard and only the one triggering payload
        # gets stored here. This does not always model reality. If fuzzing a
        # field triggers an issue, you should thoroughly fuzz-test that field
        # separately.

        # TODO: Put everything into single column, so that is instantly query as well? JSON field would allow structure
        # This really forces the DB structure and semantics, we don't want that!

        hits = (
            session.query(FuzzerIssue)
            .filter(FuzzerIssue.scenario_id == self.scenario_id)
            .filter(FuzzerIssue.req_method == self.req_method)
            .filter(FuzzerIssue.resp_statuscode == self.resp_statuscode)
            .filter(FuzzerIssue.server_protocol_error == self.server_protocol_error)
            .filter(FuzzerIssue.server_error_text_detected == self.server_error_text_detected)
            .filter(FuzzerIssue.server_error_text_matched == self.server_error_text_matched)
            .filter(FuzzerIssue.server_timeout == self.server_timeout)
            .all()
        )
        return len(hits) > 0

    @staticmethod
    def from_resp_or_exc(scenario_id, resp_or_exc):

        issue = FuzzerIssue(
            new_issue=True,
            timestamp=datetime.datetime.utcnow(),  # misleading...
            test_runner_host='FIXME',
            scenario_id=scenario_id,
        )

        if isinstance(resp_or_exc, RequestException):
            e = resp_or_exc
            if e.request:
                issue.req_headers = bytes(json.dumps(dict(e.request.headers)), 'utf-8')
                issue.req_body = bytes(e.request.body, 'utf-8')
                issue.url = e.request.url
                issue.req_method = e.request.method
            if e.response:
                issue.resp_statuscode = e.response.status_code
                issue.resp_headers = bytes(json.dumps(dict(e.response.headers)), 'utf-8')
                issue.resp_body = bytes(e.response.text, 'utf-8')
                issue.resp_history = bytes(e.response.history, 'utf-8')

            if isinstance(e, Timeout):
                issue.server_timeout = True
            else:
                issue.server_protocol_error = '{}: {}'.format(e.__class__.__name__, e)  # TODO: Add stacktrace!

        elif isinstance(resp_or_exc, Response):
            resp = resp_or_exc
            issue.req_headers = bytes(json.dumps(dict(resp.request.headers)), 'utf-8')
            if not isinstance(resp.request.body,str):
                issue.req_body = resp.request.body
            else:
                issue.req_body = bytes(resp.request.body, 'utf-8')
            issue.url = resp.request.url
            issue.req_method = resp.request.method
            issue.resp_statuscode = resp.status_code
            issue.resp_headers = bytes(json.dumps(dict(resp.headers)), 'utf-8')
            issue.resp_body = bytes(resp.text, 'utf-8')
            #issue.resp_history = bytes(resp.history, 'utf-8')
            issue.resp_history = b'history'

            if hasattr(resp, 'server_error_text_matched'):  # Hacky!
                issue.server_error_text_detected = True
                issue.server_error_text_matched = resp.server_error_text_matched
        else:
            raise NotImplemented

        return issue
