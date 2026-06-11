"""Smoke tests for the mssh-admin web portal.

These don't hit a real CA; they stub CAClient with a fake that
returns canned shapes matching the real API. Goal is to verify
every route renders with status 200 and the expected scaffolding.

Tests: §11, §11.3.1, §11.3.2, §11.3.4
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

flask = pytest.importorskip('flask')

from mssh.admin.web import create_app


SAMPLE_SERVERS = [
    {'name': 'srv-acct',  'groups': ['accounting'],   'mtls_subject': 'CN=srv-acct',
     'enrolled_at': '2026-05-19T00:00:00Z'},
    {'name': 'srv-sales', 'groups': ['sales'],        'mtls_subject': 'CN=srv-sales',
     'enrolled_at': '2026-05-19T00:01:00Z'},
    {'name': 'srv-hr',    'groups': ['hr'],           'mtls_subject': 'CN=srv-hr',
     'enrolled_at': '2026-05-19T00:02:00Z'},
]

SAMPLE_USERS = [
    {
        'username': 'alice',
        'enrolled_at': '2026-05-19T00:10:00Z',
        'keys': [{'key_type': 'ssh-ed25519',
                  'fingerprint': 'SHA256:abc',
                  'type': 'pubkey', 'principals': []}],
        'policies': [{'id': 'pol-001',
                      'server_groups': ['accounting'],
                      'servers': [],
                      'channels': ['session']}],
    },
    {
        'username': 'bob',
        'enrolled_at': '2026-05-19T00:11:00Z',
        'keys': [{'key_type': 'ssh-ed25519',
                  'fingerprint': 'SHA256:def',
                  'type': 'pubkey', 'principals': []}],
        'policies': [{'id': 'pol-002',
                      'server_groups': ['sales'],
                      'servers': [],
                      'channels': ['session']}],
    },
]

SAMPLE_ADMINS = [
    {'name': 'bootstrap-admin', 'role': 'superuser',
     'mtls_subject': 'CN=bootstrap-admin'},
]

SAMPLE_AUDIT = {
    'entries': [
        {'timestamp': '2026-05-19T12:00:00Z',
         'decision': 'granted',
         'identity': {'username': 'alice'},
         'server':   {'canonical_name': 'srv-acct'},
         'reason': None, 'detail': None},
        {'timestamp': '2026-05-19T12:01:00Z',
         'decision': 'denied',
         'identity': {'username': 'alice'},
         'server':   {'canonical_name': 'srv-sales'},
         'reason': 'no_matching_policy',
         'detail': "user 'alice' has no policy granting access"},
    ],
}


@pytest.fixture
def client():
    """Build a Flask test client with a stubbed CAClient."""
    fake = MagicMock()
    fake.server_list.return_value = SAMPLE_SERVERS
    fake.user_list.return_value = SAMPLE_USERS
    fake.admin_list.return_value = SAMPLE_ADMINS
    fake.audit.return_value = SAMPLE_AUDIT
    app = create_app(fake)
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


def test_dashboard(client):
    """Verifies §11.3.1 — dashboard renders host/user counts and sidebar."""
    r = client.get('/')
    assert r.status_code == 200
    body = r.data.decode()
    assert 'mssh-admin' in body
    assert '3' in body                    # 3 hosts
    assert '2' in body                    # 2 users
    # Sidebar links present
    for link in ('Dashboard', 'Users', 'Groups', 'Hosts', 'Audit log'):
        assert link in body


def test_users_list_and_expand_panel(client):
    """Verifies §11.3.2 — users page lists users with expandable detail panel."""
    r = client.get('/users')
    assert r.status_code == 200
    body = r.data.decode()
    assert 'alice' in body and 'bob' in body
    # Each row has a chevron + expand-target reference
    assert 'detail-user-1' in body and 'detail-user-2' in body
    # Per-row action button rendered
    assert 'user-pki-export' in body
    # The expand-detail panel includes the policy + key data
    assert 'pol-001' in body
    assert 'SHA256:abc' in body


def test_hosts_list_and_actions(client):
    """Verifies §11.3.2 — hosts page lists servers with mTLS subject + actions."""
    r = client.get('/hosts')
    assert r.status_code == 200
    body = r.data.decode()
    assert 'srv-acct' in body
    assert 'server-mtls-export' in body
    # mTLS subject visible
    assert 'CN=srv-acct' in body


def test_groups_aggregation(client):
    r = client.get('/groups')
    assert r.status_code == 200
    body = r.data.decode()
    # accounting group should show 1 host + 1 user-with-policy (alice).
    assert 'accounting' in body
    assert 'srv-acct' in body
    assert 'alice' in body


def test_audit_renders(client):
    """Verifies §11.3.4 — audit page renders granted/denied entries."""
    r = client.get('/audit')
    assert r.status_code == 200
    body = r.data.decode()
    assert 'granted' in body and 'denied' in body
    assert 'no_matching_policy' in body


def test_audit_filters_propagate(client):
    """Verifies §11.3.4 — audit filter form preserves user-supplied values."""
    r = client.get('/audit?decision=denied&user=alice&limit=5')
    assert r.status_code == 200
    # Verify the form remembers what was queried
    body = r.data.decode()
    assert 'value="alice"' in body
    assert 'value="5"' in body


def test_server_mtls_reissue(client, monkeypatch):
    """POSTing /api/server/<name>/mtls re-enrolls the server and returns
    a tarball with three files."""
    fake = client.application.config['CA_CLIENT']
    fake.server_remove.return_value = {'status': 'ok'}
    fake.server_add.return_value = {
        'credentials': {
            'cert_pem': '-----BEGIN CERT-----\nfoo\n-----END CERT-----\n',
            'key_pem':  '-----BEGIN KEY-----\nbar\n-----END KEY-----\n',
        },
    }
    # ca_pem helper reads from disk; stub it.
    monkeypatch.setattr('mssh.admin.web.views._ca_pem',
                        lambda: '-----BEGIN CA-CERT-----\nbaz\n-----END CA-CERT-----\n')

    r = client.post('/api/server/srv-acct/mtls')
    assert r.status_code == 200
    assert r.mimetype == 'application/x-tar'
    # Tarball should contain the three expected names.
    import io, tarfile
    tar = tarfile.open(fileobj=io.BytesIO(r.data), mode='r')
    names = set(tar.getnames())
    assert names == {'ca-cert.pem', 'srv-acct-cert.pem', 'srv-acct-key.pem'}
    # CA-side calls happened in the right order.
    fake.server_remove.assert_called_once_with('srv-acct')
    fake.server_add.assert_called_once_with('srv-acct', groups=['accounting'])


def test_server_mtls_missing_404(client):
    r = client.post('/api/server/nonexistent/mtls')
    assert r.status_code == 404


def test_user_pki_returns_501(client):
    """v1 returns 501 with a pointer to mint-user-pki.py."""
    r = client.post('/api/user/alice/pki')
    assert r.status_code == 501
    body = r.get_json()
    assert body['error'] == 'not_implemented'
    assert 'mint-user-pki.py' in body['detail']
