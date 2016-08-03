import json
import urlparse
import uuid
import os

import pytest
from mittn.fuzzer.fuzzing import Archiver, PythonRadamsa, AnomalyGenerator, Client, Checker, Issue, MittnFuzzer
from pastry.auth.token_provider import OAuth2ClientCredentialsTokenProvider
from wires.env.core import read_config

from fscs.sdk.api_client import ContainerApiClient, ContainerAuth

THIS_DIR = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture(scope='session')
def conf(request):
    conf_ = read_config(THIS_DIR)
    return conf_


@pytest.fixture(scope='session')
def auth(request, conf):
    user_uuid = str(uuid.uuid4())
    tenant_id = 'security-tests'

    oneid = conf['settings']['oneids'].values()[0]
    oneid_test = conf['test']['oneids'].values()[0]

    token_provider = OAuth2ClientCredentialsTokenProvider(
        urlparse.urljoin(oneid['url'], 'as/token.oauth2'),
        client_id=oneid_test['test_username'],
        client_secret=oneid_test['test_password'],
        verify=oneid['verify_ssl']
    )
    token = token_provider.fetch().access_token
    auth_ = ContainerAuth(user_uuid, tenant_id, token)

    return auth_


@pytest.fixture(scope='session')
def mittn(request):
    mittn_ = MittnFuzzer('sqlite:////home/musttu/Code/projects/cs/cs/repo.sqlite')

    # Pre: Ensure there are no leftovers from previous runs
    assert mittn_.archiver.new_issue_count() == 0, 'Unprocessed findings from past runs found in database!'

    return mittn_


@pytest.fixture()
def api_client(request, conf, auth):
    client = ContainerApiClient(
        conf['backend']['public_url'],
        auth.token,
        auth.user_uuid,
        auth.tenant_id,
        verify=False
    )
    return client


def test_post_containers_dynamic_anomalies(conf, auth, mittn):

    submission = {
        'name': 'SEC-test',
        'context': 'test-security',
        'items': ['dataA', 'dataB']
    }

    # OK: Send a valid request to ensure everything is ok
    resp_or_exc = mittn.client.request_safe(
        url=urlparse.urljoin(conf['backend']['public_url'], '/container-api/v2/containers'),
        method='POST',
        json=submission,
        auth=auth,
        verify=False,
        timeout=30
    )
    assert not mittn.checker.check(resp_or_exc, allowed_status_codes=[201]), 'Valid case did not pass: %s' + str(resp_or_exc)

    # OK: Bombard fuzzed requests, exception is that these pass
    for injected_submission in mittn.generator.generate_anomalies(submission, [submission], 100):

        # Just return the JSON representation, and output as raw if requested.
        # The latin1 encoding is a hack that just allows a 8-bit-clean byte-wise
        # output path. Using UTF-8 here would make Unicode libraries barf when using
        # fuzzed data. The character set is communicated to the client in the
        # HTTP headers anyway, so this shouldn't have an effect on efficacy.
        # XXX: So in other words, we may send them complete garbage
        payload = json.dumps(injected_submission, encoding='iso-8859-1')

        resp_or_exc = mittn.client.request_safe(
            url=urlparse.urljoin(conf['backend']['public_url'], '/container-api/v2/containers'),
            method='POST',
            data=payload,
            headers={'Content-Type': 'application/json'},
            auth=auth,
            verify=False,
            timeout=30
        )
        if mittn.checker.check(
                resp_or_exc,
                body_errors=Checker.BODY_ERROR_LIST,
                disallowed_status_codes=[500] + range(502, 599+1)  # 501 Not Implemented is ok...
        ):
            mittn.archiver.add_if_not_found(Issue.from_resp_or_exc('test_post_containers_dynamic_anomalies', resp_or_exc))

    assert mittn.archiver.new_issue_count() == 0, '%s new findings were found!'


def test_post_containers_static_anomalies(conf, auth, mittn):

    # OK: Send a valid request to ensure everything is ok
    resp_or_exc = mittn.client.request_safe(
        url=urlparse.urljoin(conf['backend']['public_url'], '/container-api/v2/containers'),
        method='POST',
        json={
            'name': 'SEC-test',
            'context': 'test-security',
            'items': ['dataA', 'dataB']
        },
        auth=auth,
        verify=False,
        timeout=30
    )
    assert not mittn.checker.check(resp_or_exc, allowed_status_codes=[201]), 'Valid case did not pass: %s' + str(resp_or_exc)

    # OK: Bombard fuzzed requests, exception is that these pass
    for injected_submission in mittn.generator.generate_static():

        payload = json.dumps(injected_submission, encoding='iso-8859-1')

        resp_or_exc = mittn.client.request_safe(
            url=urlparse.urljoin(conf['backend']['public_url'], '/container-api/v2/containers'),
            method='POST',
            data=payload,
            headers={'Content-Type': 'application/json'},
            auth=auth,
            verify=False,
            timeout=30
        )
        if mittn.checker.check(
                resp_or_exc,
                body_errors=Checker.BODY_ERROR_LIST,
                disallowed_status_codes=[500] + range(502, 599+1)  # 501 Not Implemented is ok...
        ):
            mittn.archiver.add_if_not_found(Issue.from_resp_or_exc('test_post_containers_static_anomalies', resp_or_exc))

    assert mittn.archiver.new_issue_count() == 0, '%s new findings were found!'


def test_post_container_items_dynamic_anomalies(mittn, conf, auth, api_client):

    # Create container to work on
    container1 = api_client.create_container(context='SEC-test', items=['data1', 'data2'])
    container_items_url = urlparse.urljoin(
        conf['backend']['public_url'],
        '/container-api/v2/containers/{}/items'.format(container1['id'])
    )

    submission = {'items': ['dataA', 'dataB', 'dataC']}

    # OK: Bombard fuzzed requests, exception is that these pass
    for injected_submission in mittn.generator.generate_anomalies(submission, [submission], 100):

        payload = json.dumps(injected_submission, encoding='iso-8859-1')

        resp_or_exc = mittn.client.request_safe(
            url=container_items_url,
            method='POST',
            data=payload,
            headers={'Content-Type': 'application/json'},
            auth=auth,
            verify=False,
            timeout=30
        )
        if mittn.checker.check(
                resp_or_exc,
                body_errors=Checker.BODY_ERROR_LIST,
                disallowed_status_codes=[500] + range(502, 599+1)  # 501 Not Implemented is ok...
        ):
            mittn.archiver.add_if_not_found(Issue.from_resp_or_exc('test_post_container_items_dynamic_anomalies', resp_or_exc))

    assert mittn.archiver.new_issue_count() == 0, '%s new findings were found!'


def test_post_container_items_static_anomalies(mittn, conf, auth, api_client):

    # Create container to work on
    container1 = api_client.create_container(context='SEC-test', items=['data1', 'data2'])
    container_items_url = urlparse.urljoin(
        conf['backend']['public_url'],
        '/container-api/v2/containers/{}/items'.format(container1['id'])
    )

    # OK: Bombard fuzzed requests, exception is that these pass
    for injected_submission in mittn.generator.generate_static():

        payload = json.dumps(injected_submission, encoding='iso-8859-1')

        resp_or_exc = mittn.client.request_safe(
            url=container_items_url,
            method='POST',
            data=payload,
            headers={'Content-Type': 'application/json'},
            auth=auth,
            verify=False,
            timeout=30
        )
        if mittn.checker.check(
                resp_or_exc,
                body_errors=Checker.BODY_ERROR_LIST,
                disallowed_status_codes=[500] + range(502, 599+1)  # 501 Not Implemented is ok...
        ):
            mittn.archiver.add_if_not_found(Issue.from_resp_or_exc('test_post_container_items_static_anomalies', resp_or_exc))

    assert mittn.archiver.new_issue_count() == 0, '%s new findings were found!'

