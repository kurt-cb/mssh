"""Certificate Revocation List (CRL) for the mssh CA.

Sequence-based, append-only CRL log. Each entry is one revocation
event:

    seq | revoked_at        | serials               | revoked_by | reason
    ----+-------------------+------------------------+------------+--------
      1 | 2026-05-20T10:00Z | ["abc123"]             | boot-admin | ad-hoc
      2 | 2026-05-23T09:00Z | ["alice-bypass-ser"]   | boot-admin | rotation

msshd clients track a ``last_crl_seq`` and fetch any entries beyond
it (``GET /v1/crl?after=N&limit=K``). The authorize response carries
the current sequence so msshd knows when it's behind.

Why not RFC 5280 CRLs? Two reasons:

  1. RFC CRLs are time-window-signed lists that grow without bound
     until next refresh. Sequence-based is simpler: each entry is a
     small atomic diff. msshd doesn't have to reparse the whole CRL
     to find what's new.
  2. mssh is already using custom X.509 critical extensions for
     authz; the CRL distribution semantics are a deliberate
     simplification on top of that. The cert format stays standard
     X.509; only the revocation channel is custom.

Persistence: JSONL append-only at the configured path. One line per
entry. Reading is line-by-line; appending is a single open(append)
write.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional


log = logging.getLogger('mssh.ca.crl')


@dataclass
class CRLEntry:
    """One revocation event."""
    seq: int
    revoked_at: str             # ISO-8601 UTC ('2026-05-18T15:30:00Z')
    serials: list[str]          # cert serials, lowercase hex (no '0x')
    revoked_by: str             # admin name
    reason: str = ''            # operator-supplied free text

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'CRLEntry':
        return cls(
            seq=int(d['seq']),
            revoked_at=str(d.get('revoked_at') or ''),
            serials=[str(s) for s in (d.get('serials') or [])],
            revoked_by=str(d.get('revoked_by') or ''),
            reason=str(d.get('reason') or ''),
        )


class CRLStore:
    """Append-only sequence-based CRL log.

    Thread-safe under a coarse-grained lock. Append is durable: each
    write fsyncs the file. Read is lazy: we walk the file from the
    start whenever ``fetch_after`` is called. Cheap until the log
    grows past tens of thousands of entries — fine for any
    realistic deployment.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        # Cached current_seq so the common-case (authorize-hot-path)
        # doesn't re-scan the file. Refreshed on append.
        self._current_seq: int = self._scan_current_seq()

    def append(self, serials: Iterable[str], *,
               revoked_by: str, reason: str = '') -> CRLEntry:
        """Append a new revocation entry. Returns the entry with its
        assigned seq.

        Empty ``serials`` is allowed (heartbeat / sequence-bump only)
        but generally meaningless — operators normally pass at least
        one serial.
        """
        seq_serials = [str(s).strip().lower() for s in serials if s]
        with self._lock:
            new_seq = self._current_seq + 1
            entry = CRLEntry(
                seq=new_seq,
                revoked_at=_now_iso(),
                serials=seq_serials,
                revoked_by=str(revoked_by),
                reason=str(reason or ''),
            )
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(entry.to_dict(), sort_keys=True,
                              separators=(',', ':')) + '\n'
            # Append + fsync for durability.
            fd = os.open(str(self.path),
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o0644)
            try:
                os.write(fd, line.encode('utf-8'))
                os.fsync(fd)
            finally:
                os.close(fd)
            self._current_seq = new_seq
            log.info('CRL appended: seq=%d serials=%s revoked_by=%s',
                     new_seq, seq_serials, revoked_by)
            return entry

    def current_seq(self) -> int:
        """The most recently assigned sequence number. ``0`` means
        the log is empty."""
        return self._current_seq

    def fetch_after(self, after_seq: int,
                    limit: Optional[int] = None) -> list[CRLEntry]:
        """Return entries with ``seq > after_seq``, optionally bounded
        by ``limit``. Entries are returned in seq-ascending order."""
        if not self.path.exists():
            return []
        out: list[CRLEntry] = []
        with self._lock:
            for entry in self._iter_all():
                if entry.seq <= after_seq:
                    continue
                out.append(entry)
                if limit is not None and len(out) >= limit:
                    break
        return out

    def _iter_all(self) -> Iterator[CRLEntry]:
        with self.path.open('r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield CRLEntry.from_dict(json.loads(line))
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    log.warning('CRL: skipping malformed line: %s', e)
                    continue

    def _scan_current_seq(self) -> int:
        """Walk the on-disk log to find the highest sequence number.
        Run once at construction so ``current_seq()`` is O(1)
        afterward."""
        if not self.path.exists():
            return 0
        try:
            highest = 0
            for entry in self._iter_all():
                if entry.seq > highest:
                    highest = entry.seq
            return highest
        except OSError as e:
            log.warning('CRL: could not scan %s: %s', self.path, e)
            return 0


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def build_x509_crl(store: CRLStore, *, signing_key, signing_cert,
                   validity_hours: int = 24) -> bytes:
    """Render the JSON CRL log as an X.509 v2 CRL signed by the given
    issuer (typically the TLS CA's key + cert).

    Consumers that expect an X.509 CRL (OpenVPN's ``--crl-verify``,
    most TLS stacks' revocation checks) fetch this via the
    ``GET /v1/crl.pem`` endpoint. The JSON CRL at ``GET /v1/crl``
    stays the canonical msshd-internal feed.

    ``validity_hours`` sets ``nextUpdate``; the CRL is regenerated on
    every fetch so consumers always get a fresh signature.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import oid

    now = _dt.datetime.now(_dt.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(signing_cert.subject)
        .last_update(now - _dt.timedelta(minutes=5))
        .next_update(now + _dt.timedelta(hours=validity_hours))
    )
    # Walk every entry, add each revoked serial. Empty log → empty
    # CRL (the path doesn't exist until the first append).
    entries = store._iter_all() if store.path.exists() else iter(())  # noqa: SLF001
    for entry in entries:
        try:
            revoked_at = _dt.datetime.strptime(
                entry.revoked_at, '%Y-%m-%dT%H:%M:%SZ'
            ).replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            revoked_at = now
        for serial_hex in entry.serials:
            try:
                serial = int(serial_hex, 16)
            except ValueError:
                continue
            rev = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revoked_at)
                .build()
            )
            builder = builder.add_revoked_certificate(rev)
    # Choose hash based on the signing key type. Ed25519 uses None;
    # EC + RSA use SHA-256.
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        is_ed25519 = isinstance(signing_key, ed25519.Ed25519PrivateKey)
    except ImportError:
        is_ed25519 = False
    crl = builder.sign(
        private_key=signing_key,
        algorithm=None if is_ed25519 else hashes.SHA256(),
    )
    return crl.public_bytes(serialization.Encoding.PEM)
