from sqlalchemy import Column, types
from sqlalchemy.ext.declarative.api import declarative_base
import datetime

from requests.exceptions import RequestException
from requests.models import Response

Base = declarative_base()

class Issue(Base):
    __abstract__ = True

    def __init__(self, **kwargs):
        # Fill in defaults (SQLAlchemy by default only has these after commit())
        for attr in self.__mapper__.column_attrs:
            if attr.key in kwargs:
                continue

            col = attr.columns[0]

            if col.default and not callable(col.default.arg):
                kwargs[attr.key] = col.default.arg

        super(Issue, self).__init__(**kwargs)

    issue_no = Column(types.Integer, primary_key=True, nullable=False)
    new_issue = Column(types.Boolean, default=False, nullable=False)
    timestamp = Column(types.DateTime(timezone=True), nullable=False)
    test_runner_host = Column(types.String, nullable=False)
    scenario_id = Column(types.String, nullable=False)
    url = Column(types.String, nullable=False)
