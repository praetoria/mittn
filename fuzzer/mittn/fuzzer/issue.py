from sqlalchemy import Column, types
from sqlalchemy.ext.declarative.api import declarative_base
import datetime

from requests.exceptions import RequestException
from requests.models import Response

import json

Base = declarative_base()

class BaseModel(Base):
    __abstract__ = True

    def __init__(self, **kwargs):
        # Fill in defaults (SQLAlchemy by default only has these after commit())
        for attr in self.__mapper__.column_attrs:
            if attr.key in kwargs:
                continue

            col = attr.columns[0]

            if col.default and not callable(col.default.arg):
                kwargs[attr.key] = col.default.arg

        super(BaseModel, self).__init__(**kwargs)

class Issue(BaseModel):
    __tablename__ = 'httpfuzzer_issues',

    # We use LargeBinary to store those fields that could contain somehow
    # bad Unicode, just in case some component downstream tries to parse
    # a string provided as Unicode.

    issue_no = Column(types.Integer, primary_key=True, nullable=False)
    new_issue = Column(types.Boolean, default=False, nullable=False)
    timestamp = Column(types.DateTime(timezone=True), nullable=False)
    test_runner_host = Column(types.String, nullable=False)
    scenario_id = Column(types.String, nullable=False)
    url = Column(types.String, nullable=False)

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

    @staticmethod
    def from_resp_or_exc(scenario_id, resp_or_exc):

        issue = Issue(
            new_issue=True,
            timestamp=datetime.datetime.utcnow(),  # misleading...
            test_runner_host='FIXME',
            scenario_id=scenario_id,
        )

        if isinstance(resp_or_exc, RequestException):
            e = resp_or_exc
            if e.request:
                issue.req_headers = bytes(json.dumps(dict(e.request.headers)), 'utf-8')
                issue.req_body = e.request.body
                issue.url = e.request.url
                issue.req_method = e.request.method
            if e.response:
                issue.resp_statuscode = e.response.status_code
                issue.resp_headers = bytes(json.dumps(dict(e.response.headers)), 'utf-8')
                issue.resp_body = e.response.text
                issue.resp_history = bytes(e.response.history, 'utf-8')

            if isinstance(e, Timeout):
                issue.server_timeout = True
            else:
                issue.server_protocol_error = '{}: {}'.format(e.__class__.__name__, e)  # TODO: Add stacktrace!

        elif isinstance(resp_or_exc, Response):
            resp = resp_or_exc
            issue.req_headers = bytes(json.dumps(dict(resp.request.headers)), 'utf-8')
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
