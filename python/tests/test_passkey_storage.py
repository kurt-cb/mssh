"""Unit tests for the mssh-passkey ceremony store."""

from __future__ import annotations

import datetime as _dt
import json

import pytest

flask = pytest.importorskip('flask')

from mssh_passkey.storage import Ceremony, CeremonyStore


def _opts() -> str:
    """Minimal valid options_json — opaque to the broker."""
    return json.dumps({
        'challenge': 'AAAA',
        'rp': {'id': 'passkey.example.com', 'name': 'mssh-passkey'},
        'user': {'id': 'YWxpY2U', 'name': 'alice', 'displayName': 'Alice'},
        'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
    })


@pytest.fixture
def store(tmp_path):
    return CeremonyStore(tmp_path / 'state.db')


def test_create_register_then_get(store):
    cer = store.create(
        ceremony_type='register',
        options_json=_opts(),
        description='Register alice',
        display_name='Alice',
        callback_url='https://mssh-ca.internal:8443/callback',
        created_by='mssh-ca',
        ttl_seconds=300,
    )
    assert cer.ceremony_id
    assert cer.outcome is None
    assert cer.consumed_at is None

    fetched = store.get(cer.ceremony_id)
    assert fetched is not None
    assert fetched.ceremony_type == 'register'
    assert fetched.options_json == _opts()
    assert fetched.created_by == 'mssh-ca'


def test_create_approve_and_record_response(store):
    cer = store.create(
        ceremony_type='approve',
        options_json=_opts(),
        description='Revoke admin cert for bob',
        display_name=None,
        callback_url='https://mssh-ca.internal:8443/callback',
        created_by='mssh-ca',
        ttl_seconds=300,
    )
    updated = store.record_response(
        cer.ceremony_id,
        outcome='approved',
        response_json='{"foo":"bar"}',
    )
    assert updated is True

    fetched = store.get(cer.ceremony_id)
    assert fetched.outcome == 'approved'
    assert fetched.response_json == '{"foo":"bar"}'
    assert fetched.consumed_at is not None
    assert fetched.callback_status == 'pending'


def test_record_response_is_idempotent(store):
    """A second response on the same ceremony returns False and
    doesn't overwrite the first."""
    cer = store.create(
        ceremony_type='approve', options_json=_opts(),
        description='X', display_name=None,
        callback_url='https://x/cb', created_by='mssh-ca',
        ttl_seconds=300)
    assert store.record_response(cer.ceremony_id,
                                 outcome='approved',
                                 response_json='{"a":1}')
    # Second call: refused.
    assert not store.record_response(cer.ceremony_id,
                                     outcome='denied',
                                     response_json='{"a":2}')
    fetched = store.get(cer.ceremony_id)
    assert fetched.outcome == 'approved'
    assert fetched.response_json == '{"a":1}'


def test_create_rejects_bad_type(store):
    with pytest.raises(ValueError, match='ceremony_type'):
        store.create(ceremony_type='nope',
                     options_json=_opts(),
                     description='X', display_name=None,
                     callback_url='https://x/cb', created_by='mssh-ca',
                     ttl_seconds=300)


def test_create_rejects_bad_json(store):
    with pytest.raises(ValueError, match='valid JSON'):
        store.create(ceremony_type='register',
                     options_json='not json',
                     description='X', display_name=None,
                     callback_url='https://x/cb', created_by='mssh-ca',
                     ttl_seconds=300)


def test_create_rejects_empty_description(store):
    with pytest.raises(ValueError, match='description'):
        store.create(ceremony_type='register',
                     options_json=_opts(),
                     description='', display_name=None,
                     callback_url='https://x/cb', created_by='mssh-ca',
                     ttl_seconds=300)


def test_create_rejects_bad_callback_scheme(store):
    with pytest.raises(ValueError, match='http'):
        store.create(ceremony_type='register',
                     options_json=_opts(),
                     description='X', display_name=None,
                     callback_url='ftp://nope', created_by='mssh-ca',
                     ttl_seconds=300)


def test_create_rejects_bad_ttl(store):
    with pytest.raises(ValueError, match='ttl_seconds'):
        store.create(ceremony_type='register',
                     options_json=_opts(),
                     description='X', display_name=None,
                     callback_url='https://x/cb', created_by='mssh-ca',
                     ttl_seconds=0)
    with pytest.raises(ValueError, match='ttl_seconds'):
        store.create(ceremony_type='register',
                     options_json=_opts(),
                     description='X', display_name=None,
                     callback_url='https://x/cb', created_by='mssh-ca',
                     ttl_seconds=99999)


def test_sweep_expired(store, monkeypatch):
    """Create a ceremony, fast-forward past expiry, sweep finds it."""
    cer = store.create(
        ceremony_type='approve', options_json=_opts(),
        description='X', display_name=None,
        callback_url='https://x/cb', created_by='mssh-ca',
        ttl_seconds=1)

    # Force expires_at into the past.
    with store._connect() as conn:
        past = (_dt.datetime.now(_dt.timezone.utc)
                - _dt.timedelta(seconds=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        conn.execute('UPDATE ceremonies SET expires_at = ? WHERE ceremony_id = ?',
                     (past, cer.ceremony_id))

    expired = store.sweep_expired()
    assert len(expired) == 1
    assert expired[0].ceremony_id == cer.ceremony_id

    fetched = store.get(cer.ceremony_id)
    assert fetched.outcome == 'expired'
    assert fetched.callback_status == 'pending'

    # Second sweep — already-expired ceremonies aren't returned again.
    again = store.sweep_expired()
    assert again == []


def test_pending_callbacks(store):
    cer1 = store.create(
        ceremony_type='approve', options_json=_opts(),
        description='X', display_name=None,
        callback_url='https://x/cb', created_by='mssh-ca',
        ttl_seconds=300)
    cer2 = store.create(
        ceremony_type='approve', options_json=_opts(),
        description='Y', display_name=None,
        callback_url='https://y/cb', created_by='mssh-ca',
        ttl_seconds=300)
    store.record_response(cer1.ceremony_id, outcome='approved',
                          response_json='{}')
    store.record_response(cer2.ceremony_id, outcome='denied',
                          response_json=None)

    pending = store.pending_callbacks()
    ids = {p.ceremony_id for p in pending}
    assert ids == {cer1.ceremony_id, cer2.ceremony_id}

    store.mark_callback_delivered(cer1.ceremony_id)
    pending = store.pending_callbacks()
    assert [p.ceremony_id for p in pending] == [cer2.ceremony_id]


def test_cancel_via_record_response(store):
    cer = store.create(
        ceremony_type='approve', options_json=_opts(),
        description='X', display_name=None,
        callback_url='https://x/cb', created_by='mssh-ca',
        ttl_seconds=300)
    assert store.record_response(cer.ceremony_id, outcome='cancelled',
                                 response_json=None)
    fetched = store.get(cer.ceremony_id)
    assert fetched.outcome == 'cancelled'
    # Cancellation doesn't schedule a callback.
    assert fetched.callback_status is None
