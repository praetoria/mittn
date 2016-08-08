import datetime
import os
import tempfile
import unittest
import uuid
import copy

from sqlalchemy.orm.session import Session
from mittn.archiver import Archiver
from mittn.fuzzer.fuzzerissue import FuzzerIssue as Issue

class test_archiver(unittest.TestCase):

    def setUp(self):
        # Whip up a sqlite database URI for testing
        self.db_file = os.path.join(tempfile.gettempdir(), 'mittn_unittest.' + str(uuid.uuid4()))
        self.db_url = 'sqlite:///' + self.db_file

    def test_dburl_not_defined(self):
        a = Archiver()
        a.init()
        assert a.session is None, "No db_url provided, should return None as connection"

    def test_create_db_connection(self):
        # Try whether an actual database connection can be opened
        a = Archiver(self.db_url)
        a.init()
        assert isinstance(a.session, Session), "An SQLAlchemy connection object was not returned"

    def test_number_of_new_false_positives(self):
        # Add a couple of false positives to database as new issues,
        # and check that the they're counted properly
        a = Archiver(self.db_url)
        a.init()

        # OK: Add one, expect count to be 1
        issue = Issue(
            issue_no = 1,
            new_issue = True,
            timestamp = datetime.datetime(2016,1,1),
            test_runner_host = 'testhost',
            scenario_id = 'test-scenario',
            url = 'test.io',
            server_timeout = False,
            server_error_text_detected = False
        )
        a.add_issue(issue)
        assert a.new_issue_count() == 1

        # OK: Add a second one, expect count to be 2
        issue = Issue(
            issue_no = 2,
            new_issue = True,
            timestamp = datetime.datetime(2016,1,1),
            test_runner_host = 'testhost',
            scenario_id = 'test-scenario',
            url = 'test.io',
            server_timeout = False,
            server_error_text_detected = False
        )
        a.add_issue(issue)
        assert a.new_issue_count() == 2


    def test_false_positive_detection(self):
        # Test whether false positives in database are identified properly
        # First add one false positive and try checking against it
        a = Archiver(self.db_url)
        a.init()
        
        test_issue = default_issue()
        a.add_issue(test_issue)
        self.assertEqual(a.known_false_positive(test_issue),
                         True, "Duplicate false positive not detected")

        # Change one of the differentiating fields, and test, and
        # add the tested one to the database.
        test_issue = default_issue()
        test_issue.scenario_id = 2 # Non-duplicate
        self.assertEqual(a.known_false_positive(test_issue),
                         False, "Not a duplicate: scenario_id different")
        a.add_issue(test_issue)

        # Repeat for all the differentiating fields
        test_issue = default_issue()
        test_issue.server_protocol_error = 'Error text'
        self.assertEqual(a.known_false_positive(test_issue),
                         False, "Not a duplicate: server_protocol_error different")
        a.add_issue(test_issue)

        test_issue = default_issue()
        test_issue.resp_statuscode = '500'
        self.assertEqual(a.known_false_positive(test_issue),
                         False, "Not a duplicate: resp_statuscode different")
        a.add_issue(test_issue)

        test_issue = default_issue()
        test_issue.server_timeout = True
        self.assertEqual(a.known_false_positive(test_issue),
                         False, "Not a duplicate: server_timeout different")
        a.add_issue(test_issue)

        test_issue = default_issue()
        test_issue.server_error_text_detected = True
        self.assertEqual(a.known_false_positive(test_issue),
                         False, "Not a duplicate: server_error_text_detected different")
        a.add_issue(test_issue)

        # Finally, test the last one again twice, now it ought to be
        # reported back as a duplicate
        self.assertEqual(a.known_false_positive(test_issue),
                         True, "A duplicate case not detected")

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except:
            pass

if __name__ == '__main__':
    unittest.main()

def default_issue():
    return Issue(
        scenario_id = 1,
        req_headers = b'headers',
        req_body = b'body',
        url = 'url',
        req_method = 'method',
        timestamp = datetime.datetime.utcnow(),
        test_runner_host = 'testhost',
        server_protocol_error = False,
        server_timeout = False,
        server_error_text_detected = False,
        server_error_text_matched = 'matched_text',
        resp_statuscode = 'statuscode',
        resp_headers = b'resp_headers',
        resp_body = b'resp_body',
        resp_history = b'resp_history'
    )
