from sqlalchemy import Column, types
from sqlalchemy.ext.declarative.api import declarative_base

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
    def from_resp_or_exc(scenario, resp_or_exc):

        issue = Issue(
            new_issue=True,
            timestamp=datetime.datetime.utcnow(),  # misleading...
            test_runner_host=HOSTNAME,
            scenario_id=scenario,
        )

        if isinstance(resp_or_exc, RequestException):
            e = resp_or_exc
            if e.request:
                issue.req_headers = json.dumps(dict(e.request.headers))
                issue.req_body = str(e.request.body)
                issue.url = e.request.url
                issue.req_method = e.request.method
            if e.response:
                issue.resp_statuscode = e.response.status_code
                issue.resp_headers = json.dumps(dict(e.response.headers))
                issue.resp_body = str(e.response.text)
                issue.resp_history = str(e.response.history)

            if isinstance(e, Timeout):
                issue.server_timeout = True
            else:
                issue.server_protocol_error = '{}: {}'.format(e.__class__.__name__, e)  # TODO: Add stacktrace!

        elif isinstance(resp_or_exc, Response):
            resp = resp_or_exc
            issue.req_headers = json.dumps(dict(resp.request.headers))
            issue.req_body = str(resp.request.body)
            issue.url = resp.request.url
            issue.req_method = resp.request.method
            issue.resp_statuscode = resp.status_code
            issue.resp_headers = json.dumps(dict(resp.headers))
            issue.resp_body = str(resp.text)
            issue.resp_history = str(resp.history)

            if hasattr(resp, 'server_error_text_matched'):  # Hacky!
                issue.server_error_text_detected = True
                issue.server_error_text_matched = resp.server_error_text_matched
        else:
            raise NotImplemented

        return issue
