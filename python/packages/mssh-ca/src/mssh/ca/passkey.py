"""WebAuthn relying-party logic for mssh-ca.

mssh-ca is the WebAuthn RP for two flows:
  - mssh-admin 2FA — challenging mssh-ca's own admins
  - external-tool RP — challenging end-users of separate apps

This module wraps the ``webauthn`` PyPI library with the parts both
flows need: generating options (registration + authentication),
verifying responses, and AAGUID-allowlist enforcement. The two
flows differ in WHICH credential store they consult; this module
takes credentials as input + emits ``PasskeyCredential`` records
or signatures.

The ``webauthn`` library is an optional dependency (the
``[passkey]`` extra). Import is lazy so operators not using
passkey 2FA don't need to install it.

See:
  - design/mssh-passkey-module.md (broker design)
  - design/admin-2fa.md (mssh-admin flow)
  - design/ca-integration.md § Passkey RP service (external-tool flow)
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from .enrollment import PasskeyCredential

log = logging.getLogger('mssh.ca.passkey')


@dataclass
class AAGUIDAllowlist:
    """In-memory representation of the per-deployment AAGUID
    allowlist. Source file shape:

        allowed_aaguids:
          - "ee882879-721c-4913-9775-3dfcce97072a"
          - ...
        require_allowlist: true
    """
    allowed: set[str]
    require_allowlist: bool

    def check(self, aaguid: str) -> Optional[str]:
        """Returns None on allow, or an error string on reject."""
        if not self.allowed:
            if self.require_allowlist:
                return ('no AAGUIDs configured in allowlist '
                        '(require_allowlist=true)')
            return None
        if aaguid.lower() not in self.allowed:
            return (f'AAGUID {aaguid!r} not in operator-approved list')
        return None

    @classmethod
    def load(cls, path: Optional[str | Path]) -> 'AAGUIDAllowlist':
        if not path:
            return cls(allowed=set(), require_allowlist=False)
        p = Path(path)
        if not p.exists():
            return cls(allowed=set(), require_allowlist=True)
        with p.open() as f:
            data = yaml.safe_load(f) or {}
        allowed = {str(x).lower().strip() for x in (data.get('allowed_aaguids') or [])}
        require = bool(data.get('require_allowlist', True))
        return cls(allowed=allowed, require_allowlist=require)


def _b64u_decode(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@dataclass
class RegistrationChallenge:
    """Server-side state for an in-flight registration ceremony.

    Stored by the caller (admin-2FA handler or external-tool handler)
    keyed by broker ceremony_id; consulted when the broker callback
    arrives carrying the attestation."""
    challenge_bytes: bytes
    rp_id: str
    expected_origin: str
    user_id: str           # the back-end-client identity (admin name OR tool/user_id)
    aaguid_allowlist: AAGUIDAllowlist


def generate_registration_options(*, rp_id: str, rp_name: str,
                                    user_id: str, display_name: str,
                                    exclude_credential_ids: list[str] | None = None,
                                    ) -> tuple[str, bytes]:
    """Build the PublicKeyCredentialCreationOptions JSON blob.

    Returns (options_json, challenge_bytes). Caller stores the
    challenge for later verification. ``user_id`` is the
    back-end-client identity; we hash it to derive the WebAuthn
    user.id (a 32-byte handle) so the same user_id always maps to
    the same handle without leaking the identity over the wire.
    """
    from webauthn import generate_registration_options as _gen
    from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
                                            ResidentKeyRequirement,
                                            UserVerificationRequirement,
                                            PublicKeyCredentialDescriptor,
                                            AuthenticatorTransport)
    from webauthn.helpers.cose import COSEAlgorithmIdentifier

    challenge = secrets.token_bytes(32)
    exclude_creds = []
    if exclude_credential_ids:
        for cid in exclude_credential_ids:
            exclude_creds.append(PublicKeyCredentialDescriptor(
                id=_b64u_decode(cid)))

    opts = _gen(
        rp_id=rp_id, rp_name=rp_name,
        user_id=_user_handle(user_id),
        user_name=user_id,
        user_display_name=display_name or user_id,
        challenge=challenge,
        timeout=300_000,
        exclude_credentials=exclude_creds or None,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.EDDSA,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )
    # The library returns a structured object; convert to JSON
    # string with binary fields encoded as base64url for the
    # browser.
    from webauthn.helpers import options_to_json
    return options_to_json(opts), challenge


def verify_registration(*, response_json: str,
                          challenge: RegistrationChallenge,
                          ) -> PasskeyCredential:
    """Verify the browser's registration response and produce a
    PasskeyCredential record ready for storage.

    Raises ValueError with an actionable message on failure
    (challenge mismatch, signature invalid, AAGUID not allowed,
    etc.)."""
    from webauthn import verify_registration_response
    from webauthn.helpers.structs import RegistrationCredential
    from webauthn.helpers.exceptions import InvalidRegistrationResponse

    try:
        cred_in = RegistrationCredential.parse_raw(response_json)
    except Exception as e:
        raise ValueError(f'response_json not parseable: {e}')

    try:
        verified = verify_registration_response(
            credential=cred_in,
            expected_challenge=challenge.challenge_bytes,
            expected_rp_id=challenge.rp_id,
            expected_origin=challenge.expected_origin,
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as e:
        raise ValueError(f'registration response invalid: {e}')

    aaguid_str = str(verified.aaguid) if verified.aaguid else ''
    err = challenge.aaguid_allowlist.check(aaguid_str)
    if err:
        raise ValueError(f'aaguid rejected: {err}')

    return PasskeyCredential(
        credential_id=_b64u_encode(verified.credential_id),
        public_key=_b64u_encode(verified.credential_public_key),
        aaguid=aaguid_str,
        sign_count=int(verified.sign_count),
        transports=list(cred_in.response.transports or []) if cred_in.response else [],
    )


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@dataclass
class AuthenticationChallenge:
    """Server-side state for an in-flight assertion ceremony."""
    challenge_bytes: bytes
    rp_id: str
    expected_origin: str
    user_id: str
    # Mapping (credential_id base64url) -> PasskeyCredential.
    # Verifier looks up the credential by the ID in the response.
    credentials_by_id: dict[str, PasskeyCredential]


def generate_authentication_options(*, rp_id: str,
                                       allow_credential_ids: list[str],
                                       ) -> tuple[str, bytes]:
    """Build PublicKeyCredentialRequestOptions. Returns
    (options_json, challenge_bytes)."""
    from webauthn import generate_authentication_options as _gen
    from webauthn.helpers.structs import (PublicKeyCredentialDescriptor,
                                            UserVerificationRequirement)
    from webauthn.helpers import options_to_json

    challenge = secrets.token_bytes(32)
    allow = [PublicKeyCredentialDescriptor(id=_b64u_decode(cid))
             for cid in allow_credential_ids]
    opts = _gen(
        rp_id=rp_id,
        challenge=challenge,
        timeout=300_000,
        allow_credentials=allow or None,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json(opts), challenge


@dataclass
class AuthenticationOutcome:
    """Successful assertion verification result."""
    credential_id: str       # base64url
    new_sign_count: int


def verify_authentication(*, response_json: str,
                            challenge: AuthenticationChallenge,
                            ) -> AuthenticationOutcome:
    """Verify the browser's assertion response. Raises ValueError
    on any failure."""
    from webauthn import verify_authentication_response
    from webauthn.helpers.structs import AuthenticationCredential
    from webauthn.helpers.exceptions import InvalidAuthenticationResponse

    try:
        cred_in = AuthenticationCredential.parse_raw(response_json)
    except Exception as e:
        raise ValueError(f'response_json not parseable: {e}')

    cred_id_b64 = _b64u_encode(cred_in.raw_id)
    stored = challenge.credentials_by_id.get(cred_id_b64)
    if not stored:
        raise ValueError(f'credential {cred_id_b64} not recognised')
    if stored.revoked_at:
        raise ValueError(f'credential {cred_id_b64} has been revoked')

    try:
        verified = verify_authentication_response(
            credential=cred_in,
            expected_challenge=challenge.challenge_bytes,
            expected_rp_id=challenge.rp_id,
            expected_origin=challenge.expected_origin,
            credential_public_key=_b64u_decode(stored.public_key),
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse as e:
        raise ValueError(f'assertion invalid: {e}')

    return AuthenticationOutcome(
        credential_id=cred_id_b64,
        new_sign_count=int(verified.new_sign_count),
    )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _user_handle(user_id: str) -> bytes:
    """Derive a stable 32-byte WebAuthn user handle from a back-end
    identity string. SHA-256 is fine — handle uniqueness within an
    RP is the only requirement; no need for un-correlatable handles
    across registrations of the same user."""
    import hashlib
    return hashlib.sha256(user_id.encode('utf-8')).digest()
