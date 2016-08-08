from sqlalchemy import create_engine#, Column, types
from sqlalchemy.orm.session import sessionmaker

from mittn.fuzzer.issue import Issue
from requests.exceptions import RequestException
from requests.models import Response

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
        Issue.metadata.create_all(db_engine)

    def known_false_positive(self, issue):
        """Check whether issue already exists in the database (usually a "false positive" if it does exist).

        :param issue:
        :return: True if a known issue, False if not.

        """
        if self.session is None:
            # No false positive db is in use, all findings are treated as new
            return False

        # Check whether we already know about this

        return issue.known_false_positive(self.session)

    def add_issue(self, issue):
        """Add a finding into the database as a new finding

        :param issue: The response data structure (see httptools.py)

        """

        # If no db in use, simply fail now
        if self.session is None:
            # XXX: Long assert messages seem to fail, so we truncate uri and submission to 200 bytes.
            truncated_submission = issue.resp_body[:200] + b"... (truncated)" if len(issue.resp_body) > 210 else issue.resp_body
            truncated_url = issue.resp_body[:200] + b"... (truncated)" if len(issue.url) > 210 else issue.url
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