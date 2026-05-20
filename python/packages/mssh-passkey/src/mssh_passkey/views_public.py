"""Public-facing (browser) endpoints.

No mTLS — the unguessable ceremony_id is the auth boundary. These
routes serve the registration + approval HTML pages and accept
the browser's response, store it, and let the callback worker
relay it to the back-end client.
"""

from __future__ import annotations

import json

from flask import (Blueprint, abort, current_app, jsonify, render_template,
                   request)

from .storage import CeremonyStore

bp_public = Blueprint('mssh_passkey_public', __name__)


def _store() -> CeremonyStore:
    return current_app.config['CEREMONY_STORE']


@bp_public.get('/')
def landing():
    return render_template('landing.html')


# ---- registration --------------------------------------------------------

@bp_public.get('/register/<ceremony_id>')
def register_page(ceremony_id: str):
    cer = _store().get(ceremony_id)
    if cer is None or cer.ceremony_type != 'register':
        return render_template('error.html',
                               message='Registration link is invalid or '
                               'expired. Ask your operator for a new one.'), 404
    if cer.is_terminal():
        return render_template('error.html',
                               message=f'This registration link has already '
                               f'been used ({cer.outcome}).'), 410
    if cer.is_expired():
        return render_template('error.html',
                               message='This registration link has '
                               'expired.'), 410

    return render_template(
        'register.html',
        ceremony_id=cer.ceremony_id,
        description=cer.description,
        display_name=cer.display_name or '',
        options_json=cer.options_json,
        expires_at=cer.expires_at,
    )


@bp_public.post('/register/<ceremony_id>/respond')
def register_respond(ceremony_id: str):
    cer = _store().get(ceremony_id)
    if cer is None or cer.ceremony_type != 'register':
        return jsonify({'ok': False, 'reason': 'not_found'}), 404
    if cer.is_terminal():
        return jsonify({'ok': False, 'reason': 'already_consumed'}), 410
    if cer.is_expired():
        return jsonify({'ok': False, 'reason': 'expired'}), 410

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({'ok': False, 'reason': 'bad_request'}), 400
    # We don't inspect the shape — just relay. The back-end client
    # is responsible for validating attestation.
    response_json = json.dumps(body, separators=(',', ':'))

    updated = _store().record_response(ceremony_id,
                                        outcome='approved',
                                        response_json=response_json)
    if not updated:
        # Race: another request just consumed it.
        return jsonify({'ok': False, 'reason': 'already_consumed'}), 409
    return jsonify({'ok': True}), 200


# ---- approval ------------------------------------------------------------

@bp_public.get('/approve/<ceremony_id>')
def approve_page(ceremony_id: str):
    cer = _store().get(ceremony_id)
    if cer is None or cer.ceremony_type != 'approve':
        return render_template('error.html',
                               message='Approval link is invalid or '
                               'expired.'), 404
    if cer.is_terminal():
        return render_template('error.html',
                               message=f'This approval link has already '
                               f'been used ({cer.outcome}).'), 410
    if cer.is_expired():
        return render_template('error.html',
                               message='This approval link has expired.'), 410

    return render_template(
        'approve.html',
        ceremony_id=cer.ceremony_id,
        description=cer.description,
        display_name=cer.display_name or '',
        options_json=cer.options_json,
        expires_at=cer.expires_at,
    )


@bp_public.post('/approve/<ceremony_id>/respond')
def approve_respond(ceremony_id: str):
    cer = _store().get(ceremony_id)
    if cer is None or cer.ceremony_type != 'approve':
        return jsonify({'ok': False, 'reason': 'not_found'}), 404
    if cer.is_terminal():
        return jsonify({'ok': False, 'reason': 'already_consumed'}), 410
    if cer.is_expired():
        return jsonify({'ok': False, 'reason': 'expired'}), 410

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({'ok': False, 'reason': 'bad_request'}), 400
    response_json = json.dumps(body, separators=(',', ':'))

    updated = _store().record_response(ceremony_id,
                                        outcome='approved',
                                        response_json=response_json)
    if not updated:
        return jsonify({'ok': False, 'reason': 'already_consumed'}), 409
    return jsonify({'ok': True}), 200


@bp_public.post('/approve/<ceremony_id>/deny')
def approve_deny(ceremony_id: str):
    cer = _store().get(ceremony_id)
    if cer is None or cer.ceremony_type != 'approve':
        return jsonify({'ok': False, 'reason': 'not_found'}), 404
    if cer.is_terminal():
        return jsonify({'ok': False, 'reason': 'already_consumed'}), 410

    updated = _store().record_response(ceremony_id,
                                        outcome='denied',
                                        response_json=None)
    if not updated:
        return jsonify({'ok': False, 'reason': 'already_consumed'}), 409
    return jsonify({'ok': True}), 200
