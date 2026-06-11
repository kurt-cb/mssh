"""Canonical response-envelope helper.

Design: §14.1 (see design/mssh_design_v1.md).

Every CA response carries an envelope:

    {
      "request_id": "<server-issued uuid>",
      "ca_server_id": "<CA's enrolled name>",
      "issued_at": "<ISO-8601 UTC>",
      "result": "granted" | "denied" | "ok" | "error" | "pending",
      "protocol_version": "...",
      ...handler-specific payload...
    }

R-3 reconciliation (2026-05-22): the envelope is added additively to
the existing response shape. Legacy fields (``status``, ``reason``,
flat granted-cert fields) are emitted alongside the new envelope so
existing in-tree consumers continue to work. A post-v1 cleanup
commit removes the legacy fields once nothing reads them.
"""
from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any

from mssh._protocol import PROTOCOL_VERSION


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def envelope(*,
             result: str,
             ca_server_id: str = 'mssh-ca',
             request_id: str | None = None) -> dict[str, Any]:
    """Build the envelope fields. Caller merges the handler payload on top.

    ``result`` is one of ``"granted"``, ``"denied"``, ``"ok"``, ``"error"``,
    ``"pending"`` (per §14.1 envelope).

    ``request_id`` defaults to a fresh uuid4 if not supplied — handlers
    that have a per-call id (e.g. inherited from a client header) should
    pass it through.
    """
    return {
        'request_id': request_id or uuid.uuid4().hex,
        'ca_server_id': ca_server_id,
        'issued_at': _now_iso(),
        'result': result,
        'protocol_version': PROTOCOL_VERSION,
    }
