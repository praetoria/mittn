from sqlalchemy import create_engine, Column, types
from sqlalchemy.ext.declarative.api import declarative_base
from sqlalchemy.orm.session import sessionmaker

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
    test_runner_host = Column(types.Text, nullable=False)
    scenario_id = Column(types.Text, nullable=False)
    url = Column(types.Text, nullable=False)

    server_protocol_error = Column(types.Text, default='')
    server_timeout = Column(types.Boolean, default=False, nullable=False)
    server_error_text_detected = Column(types.Boolean, default=False, nullable=False)
    server_error_text_matched = Column(types.Text, default='')

    req_method = Column(types.Text, default='')
    req_headers = Column(types.LargeBinary, default='')
    req_body = Column(types.LargeBinary, default='')

    resp_statuscode = Column(types.Text, default='')
    resp_headers = Column(types.LargeBinary, default='')
    resp_body = Column(types.LargeBinary, default='')
    resp_history = Column(types.LargeBinary, default='')

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

class Archiver(object):

    def __init__(self, db_url=None):
        self.db_url = db_url
        self.session = None

    def init(self):
        """Opens the database specified in the feature file and creates tables if not already created.

        :return: A database handle, or None if no database in use

        """
        if not self.db_url:
            return None  # No false positives database is in use

        # Connect to the database
        db_engine = create_engine(self.db_url)
        Session = sessionmaker(bind=db_engine)
        self.session = Session()

        # Create DB tables (has no effect, if they already exist)
        Base.metadata.create_all(db_engine)

    def known_false_positive(self, issue):
        """Check whether issue already exists in the database (usually a "false positive" if it does exist).

        :param issue:
        :return: True if a known issue, False if not.

        """
        if self.session is None:
            # No false positive db is in use, all findings are treated as new
            return False

        # XXX: Because each fuzz case is likely to be separate, we cannot store
        # all those. Two different fuzz cases that elicit a similar response are
        # indistinguishable in this regard and only the one triggering payload
        # gets stored here. This does not always model reality. If fuzzing a
        # field triggers an issue, you should thoroughly fuzz-test that field
        # separately.

        # TODO: Put everything into single column, so that is instantly query as well? JSON field would allow structure
        # This really forces the DB structure and semantics, we don't want that!

        # Check whether we already know about this
        hits = (
            self.session.query(Issue)
            .filter(Issue.scenario_id == issue.scenario_id)
            .filter(Issue.req_method == issue.req_method)
            .filter(Issue.resp_statuscode == issue.resp_statuscode)
            .filter(Issue.server_protocol_error == issue.server_protocol_error)
            .filter(Issue.server_error_text_detected == issue.server_error_text_detected)
            .filter(Issue.server_error_text_matched == issue.server_error_text_matched)
            .filter(Issue.server_timeout == issue.server_timeout)
            .all()
        )

        return len(hits) > 0

    def add_issue(self, issue):
        """Add a finding into the database as a new finding

        :param issue: The response data structure (see httptools.py)

        """

        # If no db in use, simply fail now
        if self.session is None:
            # XXX: Long assert messages seem to fail, so we truncate uri and submission to 200 bytes.
            truncated_submission = issue.resp_body[:200] + "... (truncated)" if len(issue.resp_body) > 210 else issue.resp_body
            truncated_url = issue.resp_body[:200] + "... (truncated)" if len(issue.url) > 210 else issue.url
            assert False, (
                "Response from server failed a check, and no errors "
                "database is in use."
                "Scenario id = {issue.scenario_id}, "
                "error = {issue.server_protocol_error}, "
                "timeout = {issue.server_timeout}, "
                "status = {issue.resp_statuscode}, "
                "URL = {url}, "
                "req_method = {issue.req_method}, "
                "submission = {submission}".format(
                    issue=issue, url=truncated_url, submission=truncated_submission
                ))

        # Add the finding into the database
        self.session.add(issue)
        self.session.commit()

    def add_if_not_found(self, issue):
        if not self.known_false_positive(issue):
            self.add_issue(issue)

    def new_issue_count(self):
        if self.session is None:
            return 0

        hits = self.session.query(Issue).filter_by(new_issue=True).all()

        return len(hits)
