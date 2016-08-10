from sqlalchemy import Column, types
import datetime

from mittn.issue import Issue

import json

class ScannerIssue(Issue):
    __tablename__ = 'headlessscanner_issues'

    # We use LargeBinary in message because it can be very big

    # XXX fields that are used in all tools come from issue.py

    severity = Column(types.Text)
    issuetype = Column(types.Text)
    issuename = Column(types.Text)
    issuedetail = Column(types.Text)
    confidence = Column(types.Text)
    host = Column(types.Text)
    port = Column(types.Text)
    protocol = Column(types.Text)
    messages = Column(types.LargeBinary)

    def unique_fields(self):
        """ These fields are used when checking for false
        positives already present in the database
        """
        return [(ScannerIssue.scenario_id, self.scenario_id),
                (ScannerIssue.url, self.url),
                (ScannerIssue.issuetype, self.issuetype)]

    @staticmethod
    def issue_from_dict(scenario_id,obj):
        issue = ScannerIssue(
                new_issue=True,
                timestamp=datetime.datetime.utcnow(),
                test_runner_host="FIXME",
                scenario_id=scenario_id,
                )
        for key in obj.keys():
            setattr(issue,key,obj[key])
        issue.messages = bytes(json.dumps(issue.messages),'utf-8')
        return issue
