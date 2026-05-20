"""mTLS-authenticated broker endpoints.

All routes here expect the request to carry ``X-Client-CN`` set by
Apache2 (production) or our in-process TLS handler (dev). The CN
must match one of ``allowed_client_cns`` in config. Requests
without a populated header are refused.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from .storage import CeremonyStore

bp_broker = Blueprint('mssh_passkey_broker', __name__)


def _config():
    return current_app.config['PASSKEY_CONFIG']


def _store() -> CeremonyStore:
    return current_app.config['CEREMONY_STORE']


def _auth_or_401():
    """Returns (client_cn, None) on success, or (None, err) where
    err is a Flask response tuple."""
    cn = request.headers.get('X-Client-CN', '').strip()
    if not cn:
        return None, (jsonify({'status': 'error', 'reason': 'unauthorized',
                                'detail': 'X-Client-CN header missing — '
                                'Apache2 mTLS validation upstream is '
                                'required'}), 401)
    if cn not in _config().allowed_client_cns:
        return None, (jsonify({'status': 'error', 'reason': 'unauthorized',
                                'detail': f'client CN {cn!r} not in '
                                'allowed_client_cns'}), 401)
    return cn, None


@bp_broker.post('/ceremony')
def create_ceremony():
    """Back-end client creates a new ceremony.

    Body:
      {type, options_json, description, display_name?, ttl_seconds,
       callback_url}

    Response (201):
      {ceremony_id, url, expires_at}
    """
    cn, err = _auth_or_401()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    try:
        cer = _store().create(
            ceremony_type=body.get('type', ''),
            options_json=body.get('options_json', ''),
            description=body.get('description', ''),
            display_name=body.get('display_name'),
            callback_url=body.get('callback_url', ''),
            created_by=cn,
            ttl_seconds=int(body.get('ttl_seconds', 300)),
        )
    except (ValueError, TypeError) as e:
        return jsonify({'status': 'error', 'reason': 'bad_request',
                        'detail': str(e)}), 400

    path = ('/register/' if cer.ceremony_type == 'register'
            else '/approve/') + cer.ceremony_id
    return jsonify({
        'status': 'ok',
        'ceremony_id': cer.ceremony_id,
        'url': _config().public_base_url + path,
        'expires_at': cer.expires_at,
    }), 201


@bp_broker.get('/ceremony/<ceremony_id>')
def get_ceremony(ceremony_id: str):
    """Back-end client polls the broker for a ceremony's status.

    Returned without `options_json` (the back-end client already
    has it) — only the outcome + response + delivery state.
    """
    _, err = _auth_or_401()
    if err:
        return err

    cer = _store().get(ceremony_id)
    if cer is None:
        return jsonify({'status': 'error', 'reason': 'not_found',
                        'detail': f'no ceremony {ceremony_id!r}'}), 404
    return jsonify({
        'status': 'ok',
        'ceremony_id': cer.ceremony_id,
        'type': cer.ceremony_type,
        'outcome': cer.outcome,
        'consumed_at': cer.consumed_at,
        'expires_at': cer.expires_at,
        'response_json': cer.response_json,
        'callback_status': cer.callback_status,
    }), 200


@bp_broker.delete('/ceremony/<ceremony_id>')
def cancel_ceremony(ceremony_id: str):
    """Back-end client cancels a pending ceremony."""
    _, err = _auth_or_401()
    if err:
        return err

    cer = _store().get(ceremony_id)
    if cer is None:
        return jsonify({'status': 'error', 'reason': 'not_found',
                        'detail': f'no ceremony {ceremony_id!r}'}), 404
    if cer.outcome is not None:
        return jsonify({'status': 'error', 'reason': 'conflict',
                        'detail': f'ceremony already terminal '
                        f'({cer.outcome})'}), 409

    _store().record_response(ceremony_id,
                              outcome='cancelled',
                              response_json=None)
    return jsonify({'status': 'ok', 'ceremony_id': ceremony_id,
                    'outcome': 'cancelled'}), 200
