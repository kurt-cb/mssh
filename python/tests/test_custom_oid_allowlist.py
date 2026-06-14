"""§15.21 operator-allowlist custom OID tests.

Covers:

- YAML parse: round-trip allowlist entries (oid, name, encoding,
  max_length, description, critical).
- CAConfig.validate(): refuse-to-start when allowlist contains an OID
  in the mssh-reserved arc.
- attach_custom_extensions(): wires allowlisted OIDs onto a cert
  builder, enforces encoding/max_length, rejects unknown references.
- Cross-check the reserved/operator-arc constants line up: arc split is
  [1, 4999] reserved, [5000, 65535] operator.

Tests: §15.21
"""
from __future__ import annotations

import datetime as _dt

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mssh.ca.cert_minter import attach_custom_extensions
from mssh.ca.config import (
    CAConfig,
    CustomOIDAllowlist,
    CustomOIDEntry,
    OPERATOR_SUB_ARC,
    RESERVED_OID_RANGES,
    _check_oid_against_reserved,
)


# ---- reserved-arc range check ---------------------------------------------


def test_arc_split_matches_design():
    """Verifies §15.21 — reserved arc is [1, 4999], operator arc is
    [5000, 65535], same prefix."""
    assert RESERVED_OID_RANGES == (
        ('1.3.6.1.4.1.55555', 1, 4999, 'mssh-reserved'),
    )
    assert OPERATOR_SUB_ARC == ('1.3.6.1.4.1.55555', 5000, 65535)


@pytest.mark.parametrize('oid', [
    '1.3.6.1.4.1.55555.1.8',      # OID_CA_BYPASS
    '1.3.6.1.4.1.55555.2.1',      # purpose marker
    '1.3.6.1.4.1.55555.3.9',      # external-use kind marker
    '1.3.6.1.4.1.55555.4999.1',   # last reserved
])
def test_reserved_oids_rejected(oid):
    """Verifies §15.21 — every OID in the reserved range fails the
    allowlist self-check with a clear error message."""
    err = _check_oid_against_reserved(oid)
    assert err is not None
    assert 'mssh-reserved' in err
    assert '5000-65535' in err   # points operator at the right range


@pytest.mark.parametrize('oid', [
    '1.3.6.1.4.1.55555.5000.1',   # first operator slot
    '1.3.6.1.4.1.55555.5001.1',   # example OEM id
    '1.3.6.1.4.1.55555.65535.99', # last operator slot
    '1.3.6.1.4.1.99999.1.1',      # arbitrary other PEN
    '2.5.29.17',                  # standard SAN OID (well-known, allowed)
])
def test_operator_sub_arc_and_other_pens_allowed(oid):
    """Verifies §15.21 — operator sub-arc + arbitrary other-PEN OIDs
    pass the reserved-range check."""
    assert _check_oid_against_reserved(oid) is None


# ---- YAML round-trip + CAConfig.validate() integration --------------------


def _write_yaml(tmp_path, extra: dict) -> str:
    """Helper: write a ca-config.yaml with the minimum R-9 fields plus
    the operator-supplied sections, return its path."""
    sk = tmp_path / 'signing-key.pem'; sk.write_text('-key-')
    sc = tmp_path / 'signing-cert.pem'; sc.write_text('-cert-')
    tc = tmp_path / 'tls-cert.pem'; tc.write_text('-cert-')
    tk = tmp_path / 'tls-key.pem'; tk.write_text('-key-')
    cca = tmp_path / 'client-ca-cert.pem'; cca.write_text('-cert-')
    base = {
        'listen': '127.0.0.1:4443',
        'signing_key': str(sk),
        'signing_cert': str(sc),
        'tls_cert': str(tc),
        'tls_key': str(tk),
        'client_ca_cert': str(cca),
        'identity_trust_roots': [str(sc)],
    }
    base.update(extra)
    p = tmp_path / 'ca-config.yaml'
    p.write_text(yaml.safe_dump(base))
    return str(p)


def test_yaml_round_trip_populates_allowlist(tmp_path):
    """Verifies §15.21 — entries land in `entries` (by-OID) and `by_name`
    (by-name); validate() accepts the config."""
    path = _write_yaml(tmp_path, {
        'custom_oids': [
            {'oid': '1.3.6.1.4.1.55555.5001.1', 'name': 'device_oem',
             'encoding': 'utf8', 'max_length': 64,
             'description': 'OEM id'},
            {'oid': '1.3.6.1.4.1.55555.5001.2', 'name': 'device_serial',
             'encoding': 'utf8', 'max_length': 128},
        ],
    })
    cfg = CAConfig.load(path)
    cfg.validate()    # no raise
    assert set(cfg.custom_oids.entries) == {
        '1.3.6.1.4.1.55555.5001.1', '1.3.6.1.4.1.55555.5001.2',
    }
    assert cfg.custom_oids.by_name == {
        'device_oem':    '1.3.6.1.4.1.55555.5001.1',
        'device_serial': '1.3.6.1.4.1.55555.5001.2',
    }
    e = cfg.custom_oids.entries['1.3.6.1.4.1.55555.5001.1']
    assert e.encoding == 'utf8'
    assert e.max_length == 64
    assert e.description == 'OEM id'


def test_validate_refuses_reserved_arc_in_allowlist(tmp_path):
    """Verifies §15.21 + §13.9.7 — allowlisting `.3.1` (an mssh-reserved
    kind marker OID) makes the CA refuse to start."""
    path = _write_yaml(tmp_path, {
        'custom_oids': [
            {'oid': '1.3.6.1.4.1.55555.3.1', 'name': 'oops',
             'encoding': 'null'},
        ],
    })
    cfg = CAConfig.load(path)
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert '15.21' in str(exc.value)
    assert '1.3.6.1.4.1.55555.3.1' in str(exc.value)
    assert 'mssh-reserved' in str(exc.value)


def test_validate_refuses_unknown_encoding(tmp_path):
    """Verifies §15.21 — unknown encoding refused at startup."""
    path = _write_yaml(tmp_path, {
        'custom_oids': [
            {'oid': '1.3.6.1.4.1.55555.5001.1', 'name': 'x',
             'encoding': 'json'},
        ],
    })
    cfg = CAConfig.load(path)
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert "json" in str(exc.value)
    assert "must be one of" in str(exc.value)


def test_validate_refuses_zero_max_length(tmp_path):
    """Verifies §15.21 — max_length must be positive."""
    path = _write_yaml(tmp_path, {
        'custom_oids': [
            {'oid': '1.3.6.1.4.1.55555.5001.1', 'name': 'x',
             'encoding': 'utf8', 'max_length': 0},
        ],
    })
    cfg = CAConfig.load(path)
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert 'max_length' in str(exc.value)


def test_no_custom_oids_section_means_empty_allowlist(tmp_path):
    """Verifies §15.21 — v0.4.x configs that lack `custom_oids:`
    get an empty allowlist (default-deny)."""
    path = _write_yaml(tmp_path, {})
    cfg = CAConfig.load(path)
    cfg.validate()
    assert cfg.custom_oids.entries == {}


# ---- attach_custom_extensions: end-to-end through a real cert builder ----


def _builder(public_key) -> x509.CertificateBuilder:
    """Verifies §15.21 — minimal CertificateBuilder shell used to
    exercise attach_custom_extensions; not signed (the test inspects
    the extension list before signing)."""
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'leaf')]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ca')]))
        .public_key(public_key)
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=1))
    )


def _allowlist() -> CustomOIDAllowlist:
    """Verifies §15.21 — operator allowlist with one entry of each
    supported encoding."""
    entries = {
        '1.3.6.1.4.1.55555.5001.1': CustomOIDEntry(
            oid='1.3.6.1.4.1.55555.5001.1', name='oem',
            encoding='utf8', max_length=8),
        '1.3.6.1.4.1.55555.5001.2': CustomOIDEntry(
            oid='1.3.6.1.4.1.55555.5001.2', name='serial_num',
            encoding='integer'),
        '1.3.6.1.4.1.55555.5001.3': CustomOIDEntry(
            oid='1.3.6.1.4.1.55555.5001.3', name='manufactured',
            encoding='null'),
        '1.3.6.1.4.1.55555.5001.4': CustomOIDEntry(
            oid='1.3.6.1.4.1.55555.5001.4', name='hash',
            encoding='octet'),
        '1.3.6.1.4.1.55555.5001.5': CustomOIDEntry(
            oid='1.3.6.1.4.1.55555.5001.5', name='model',
            encoding='printable'),
    }
    by_name = {e.name: e.oid for e in entries.values()}
    return CustomOIDAllowlist(entries=entries, by_name=by_name)


def test_attach_utf8_extension():
    """Verifies §15.21 — utf8-encoded extension lands on the builder
    with the operator's value."""
    pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    builder = _builder(pk)
    builder = attach_custom_extensions(
        builder,
        [{'oid': '1.3.6.1.4.1.55555.5001.1', 'value': 'acme'}],
        _allowlist())
    cert = builder.sign(
        ec.generate_private_key(ec.SECP256R1()),
        algorithm=__import__('cryptography.hazmat.primitives.hashes',
                              fromlist=['SHA256']).SHA256())
    ext = cert.extensions.get_extension_for_oid(
        x509.ObjectIdentifier('1.3.6.1.4.1.55555.5001.1'))
    # UTF8String DER = tag 0x0c + length + value bytes
    assert ext.value.value.startswith(b'\x0c\x04acme')


def test_attach_by_name_reference():
    """Verifies §15.21 — operator can reference by `name` instead of
    the dotted OID, and the right entry is found."""
    pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    builder = _builder(pk)
    builder = attach_custom_extensions(
        builder, [{'name': 'oem', 'value': 'acme'}], _allowlist())
    cert = builder.sign(
        ec.generate_private_key(ec.SECP256R1()),
        algorithm=__import__('cryptography.hazmat.primitives.hashes',
                              fromlist=['SHA256']).SHA256())
    cert.extensions.get_extension_for_oid(
        x509.ObjectIdentifier('1.3.6.1.4.1.55555.5001.1'))  # no raise


def test_attach_rejects_not_on_allowlist():
    """Verifies §15.21 — OID not on the allowlist raises ValueError."""
    pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(ValueError) as exc:
        attach_custom_extensions(
            _builder(pk),
            [{'oid': '1.3.6.1.4.1.99999.99', 'value': 'x'}],
            _allowlist())
    assert 'not in the operator allowlist' in str(exc.value)


def test_attach_enforces_max_length():
    """Verifies §15.21 — value longer than the allowlist's max_length
    is rejected."""
    pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(ValueError) as exc:
        attach_custom_extensions(
            _builder(pk),
            [{'name': 'oem', 'value': 'this-is-way-too-long-for-the-eight-byte-cap'}],
            _allowlist())
    assert 'max_length' in str(exc.value)


def test_attach_integer_encoding():
    """Verifies §15.21 — integer encoding accepts int + str-of-int."""
    pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    builder = _builder(pk)
    builder = attach_custom_extensions(
        builder, [{'name': 'serial_num', 'value': 12345}], _allowlist())
    cert = builder.sign(
        ec.generate_private_key(ec.SECP256R1()),
        algorithm=__import__('cryptography.hazmat.primitives.hashes',
                              fromlist=['SHA256']).SHA256())
    ext = cert.extensions.get_extension_for_oid(
        x509.ObjectIdentifier('1.3.6.1.4.1.55555.5001.2'))
    # INTEGER DER for 12345 = tag 0x02 + length 0x02 + 0x30 0x39
    assert ext.value.value == b'\x02\x02\x30\x39'


def test_attach_integer_rejects_non_integer():
    """Verifies §15.21 — integer encoding rejects garbage."""
    pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(ValueError):
        attach_custom_extensions(
            _builder(pk),
            [{'name': 'serial_num', 'value': 'not-a-number'}],
            _allowlist())


def test_attach_no_allowlist_with_request_rejected():
    """Verifies §15.21 + §13.9.7 — if the CA has no allowlist but the
    operator sends a custom_oids list, the request is rejected."""
    pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(ValueError) as exc:
        attach_custom_extensions(
            _builder(pk),
            [{'oid': '1.3.6.1.4.1.55555.5001.1', 'value': 'x'}],
            None)
    assert 'default-deny' in str(exc.value)


def test_attach_no_request_is_noop():
    """Verifies §15.21 — empty/missing custom_oids list does nothing,
    even when allowlist is None."""
    pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    b1 = _builder(pk)
    b2 = attach_custom_extensions(b1, None, None)
    b3 = attach_custom_extensions(b1, [], _allowlist())
    # Just confirms no exception; the builder object is the same shape.
    assert b2 is b1
    assert b3 is b1
