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

class ScannerIssue(BaseModel):
    __tablename__ = 'headlessscanner_issues'

    # We use LargeBinary to store those fields that could contain somehow
    # bad Unicode, just in case some component downstream tries to parse
    # a string provided as Unicode.

    issue_no = Column(types.Integer, primary_key=True, nullable=False)
    new_issue = Column(types.Boolean, default=False, nullable=False)
    timestamp = Column(types.DateTime(timezone=True), nullable=False)
    test_runner_host = Column(types.String, nullable=False)
    scenario_id = Column(types.String, nullable=False)
    url = Column(types.String, nullable=False)
    severity = Column(types.Text, nullable=False)
    issuetype = Column(types.Text, nullable=False)
    issuename = Column(types.Text, nullable=False)
    issuedetail = Column(types.Text, nullable=False)
    confidence = Column(types.Text, nullable=False)
    host = Column(types.Text, nullable=False)
    port = Column(types.Text, nullable=False)
    protocol = Column(types.Text, nullable=False)
    messages = Column(types.LargeBinary, nullable=False)

    def known_false_positive(self,session):

    """Check whether a finding already exists in the database (usually
    a "false positive" if it does exist)
    """
        hits = (
            session.query(ScannerIssue)
            .filter(ScannerIssue.scenario_id == self.scenario_id)
            .filter(ScannerIssue.url == self.url)
            .filter(ScannerIssue.issuetype == self.issuetype)
            .all()
        )
        return len(hits) > 0
    # TODO: function to create new issues
