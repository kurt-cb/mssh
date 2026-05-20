"""Tests for the broker + public Flask routes.

Stubs Apache2's X-Client-CN header to exercise mTLS-gated routes
without standing up real TLS.
"""

from __future__ import annotations

import json

import pytest

flask = pytest.importorskip('flask')

from mssh_passkey.app import create_app
from mssh_passkey.config import (CallbackConfig, Config, ListenConfig,
                                  RPConfig)


def _opts():
    return json.dumps({
        'challenge': 'AAAA',
        'rp': {'id': 'passkey.example.com', 'name': 'mssh-passkey'},
        'user': {'id': 'YWxpY2U', 'name': 'alice', 'displayName': 'Alice'},
        'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
    })


@pytest.fixture
def app(tmp_path):
    cfg = Config(
        front_end='apache',
        listen=ListenConfig(bind='127.0.0.1', port=5000),
        allowed_client_cns=['mssh-ca'],
        callback=CallbackConfig(),
        rp=RPConfig(rp_id='passkey.example.com'),
        database_path=str(tmp_path / 'state.db'),
        public_base_url='https://passkey.example.com',
    )
    app = create_app(cfg)
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    with app.test_client() as c:
        yield c


@pytest.fixture
def mtls_headers():
    """Headers Apache2 would set in production."""
    return {'X-Client-CN': 'mssh-ca'}


# ---- broker auth ---------------------------------------------------------

def test_broker_requires_x_client_cn(client):
    r = client.post('/broker/ceremony', json={})
    assert r.status_code == 401
    assert 'X-Client-CN' in r.get_json()['detail']


def test_broker_refuses_unknown_cn(client):
    r = client.post('/broker/ceremony', json={},
                    headers={'X-Client-CN': 'attacker'})
    assert r.status_code == 401
    assert 'allowed_client_cns' in r.get_json()['detail']


# ---- /broker/ceremony POST ----------------------------------------------

def test_create_ceremony_register(client, mtls_headers):
    body = {
        'type': 'register',
        'options_json': _opts(),
        'description': 'Register alice',
        'display_name': 'Alice',
        'callback_url': 'https://mssh-ca.internal:8443/callback',
        'ttl_seconds': 300,
    }
    r = client.post('/broker/ceremony', json=body, headers=mtls_headers)
    assert r.status_code == 201, r.data
    out = r.get_json()
    assert out['status'] == 'ok'
    assert out['ceremony_id']
    assert out['url'].startswith('https://passkey.example.com/register/')
    assert out['url'].endswith(out['ceremony_id'])


def test_create_ceremony_approve(client, mtls_headers):
    body = {
        'type': 'approve',
        'options_json': _opts(),
        'description': 'Revoke admin cert for bob',
        'callback_url': 'https://mssh-ca.internal:8443/callback',
        'ttl_seconds': 300,
    }
    r = client.post('/broker/ceremony', json=body, headers=mtls_headers)
    assert r.status_code == 201
    assert r.get_json()['url'].startswith(
        'https://passkey.example.com/approve/')


def test_create_ceremony_400_on_bad_type(client, mtls_headers):
    body = {'type': 'nope', 'options_json': _opts(),
            'description': 'X',
            'callback_url': 'https://x/cb', 'ttl_seconds': 300}
    r = client.post('/broker/ceremony', json=body, headers=mtls_headers)
    assert r.status_code == 400


def test_create_ceremony_400_on_bad_json(client, mtls_headers):
    body = {'type': 'register', 'options_json': 'not json',
            'description': 'X',
            'callback_url': 'https://x/cb', 'ttl_seconds': 300}
    r = client.post('/broker/ceremony', json=body, headers=mtls_headers)
    assert r.status_code == 400


# ---- /broker/ceremony GET ------------------------------------------------

def test_get_ceremony(client, mtls_headers):
    r = client.post('/broker/ceremony', json={
        'type': 'approve', 'options_json': _opts(),
        'description': 'X',
        'callback_url': 'https://x/cb', 'ttl_seconds': 300,
    }, headers=mtls_headers)
    cid = r.get_json()['ceremony_id']

    r2 = client.get(f'/broker/ceremony/{cid}', headers=mtls_headers)
    assert r2.status_code == 200
    out = r2.get_json()
    assert out['ceremony_id'] == cid
    assert out['outcome'] is None
    assert out['callback_status'] is None


def test_get_ceremony_404(client, mtls_headers):
    r = client.get('/broker/ceremony/nope', headers=mtls_headers)
    assert r.status_code == 404


# ---- /broker/ceremony DELETE (cancel) -----------------------------------

def test_cancel_ceremony(client, mtls_headers):
    r = client.post('/broker/ceremony', json={
        'type': 'approve', 'options_json': _opts(),
        'description': 'X',
        'callback_url': 'https://x/cb', 'ttl_seconds': 300,
    }, headers=mtls_headers)
    cid = r.get_json()['ceremony_id']

    r2 = client.delete(f'/broker/ceremony/{cid}', headers=mtls_headers)
    assert r2.status_code == 200
    assert r2.get_json()['outcome'] == 'cancelled'

    # Cancelling again returns 409.
    r3 = client.delete(f'/broker/ceremony/{cid}', headers=mtls_headers)
    assert r3.status_code == 409


# ---- public browser endpoints --------------------------------------------

def test_register_page_renders(client, mtls_headers):
    r = client.post('/broker/ceremony', json={
        'type': 'register', 'options_json': _opts(),
        'description': 'Register a new authenticator for alice',
        'display_name': 'Alice',
        'callback_url': 'https://x/cb', 'ttl_seconds': 300,
    }, headers=mtls_headers)
    cid = r.get_json()['ceremony_id']

    page = client.get(f'/register/{cid}')
    assert page.status_code == 200
    body = page.data.decode()
    assert 'Register a new authenticator for alice' in body
    assert 'Alice' in body
    # The options_json should be present (serialized into the page).
    assert 'passkey.example.com' in body


def test_register_page_404_for_unknown(client):
    r = client.get('/register/does-not-exist')
    assert r.status_code == 404


def test_register_respond(client, mtls_headers):
    r = client.post('/broker/ceremony', json={
        'type': 'register', 'options_json': _opts(),
        'description': 'X',
        'callback_url': 'https://x/cb', 'ttl_seconds': 300,
    }, headers=mtls_headers)
    cid = r.get_json()['ceremony_id']

    # Browser POSTs an attestation response. No mTLS — public endpoint.
    response_body = {
        'id': 'cred-abc',
        'rawId': 'AAAA',
        'type': 'public-key',
        'response': {
            'clientDataJSON': 'BBBB',
            'attestationObject': 'CCCC',
        },
    }
    resp = client.post(f'/register/{cid}/respond', json=response_body)
    assert resp.status_code == 200
    assert resp.get_json()['ok'] is True

    # The broker now has the response_json stored for callback delivery.
    poll = client.get(f'/broker/ceremony/{cid}', headers=mtls_headers)
    out = poll.get_json()
    assert out['outcome'] == 'approved'
    assert out['callback_status'] == 'pending'
    stored = json.loads(out['response_json'])
    assert stored['id'] == 'cred-abc'


def test_register_respond_idempotent(client, mtls_headers):
    r = client.post('/broker/ceremony', json={
        'type': 'register', 'options_json': _opts(),
        'description': 'X',
        'callback_url': 'https://x/cb', 'ttl_seconds': 300,
    }, headers=mtls_headers)
    cid = r.get_json()['ceremony_id']
    body = {'id': 'first', 'rawId': 'AAAA', 'type': 'public-key',
            'response': {'clientDataJSON': 'BBBB', 'attestationObject': 'CCCC'}}
    assert client.post(f'/register/{cid}/respond', json=body).status_code == 200
    # Replay: refused. 410 (Gone) because the page-level
    # is_terminal() check fires before the DB attempt; 409
    # would only happen on a true TOCTOU race.
    assert client.post(f'/register/{cid}/respond', json=body).status_code == 410


def test_approve_deny_path(client, mtls_headers):
    r = client.post('/broker/ceremony', json={
        'type': 'approve', 'options_json': _opts(),
        'description': 'Revoke X',
        'callback_url': 'https://x/cb', 'ttl_seconds': 300,
    }, headers=mtls_headers)
    cid = r.get_json()['ceremony_id']

    resp = client.post(f'/approve/{cid}/deny')
    assert resp.status_code == 200

    poll = client.get(f'/broker/ceremony/{cid}', headers=mtls_headers)
    assert poll.get_json()['outcome'] == 'denied'


def test_landing(client):
    r = client.get('/')
    assert r.status_code == 200
    assert b'mssh-passkey' in r.data
