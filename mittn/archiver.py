from sqlalchemy import create_engine
from sqlalchemy.orm.session import sessionmaker

class Archiver(object):

    def __init__(self, db_url=None):
        self.db_url = db_url
        self.session = None

    def init(self,issuecls=None):
        """Opens the database specified in the feature file and creates tables if not already created.

        """
        if not self.db_url or not issuecls:
            return None  # No false positives database is in use

        # Connect to the database
        db_engine = create_engine(self.db_url)
        Session = sessionmaker(bind=db_engine)
        self.session = Session()

        # Create DB tables (has no effect, if they already exist)
        issuecls.metadata.create_all(db_engine)

    def known_false_positive(self, issue):
        """Check whether issue already exists in the database (usually a "false positive" if it does exist).

        :param issue:
        :return: True if a known issue, False if not.

        """
        if self.session is None:
            # No false positive db is in use, all findings are treated as new
            return False

        # Check whether we already know about this

        q = self.session.query(type(issue))
        # filter all corresponding fields
        for cls_attr, attr in issue.unique_fields():
            q = q.filter(cls_attr == attr)

        hits = q.all()
        return len(hits) > 0

    def add_issue(self, issue):
        """Add a finding into the database as a new finding

        :param issue: a db object created from issue class (see issue.py)

        """

        # If no db in use, simply fail now
        if self.session is None:
            raise ValueError(
                "Response from server failed a check, and no errors "
                "database is in use."
                "Scenario id = {issue.scenario_id}, "
                "URL = {issue.url}, ".format(
                    issue=issue
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

        hits = self.session.query(type(self)).filter_by(new_issue=True).all()

        return len(hits)
