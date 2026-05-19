"""CA-side renderer for the inner sshd config template.

The CA produces the rendered ``sshd_config`` per session. msshd substitutes
``{LOCAL_*}`` markers (its own paths) and writes the result; it has no
opinion about the rest of the config. This module is the rendering core.

## Marker grammar

Two namespaces of named substitutions appear in the template:

  - ``{LOCAL_*}`` — substituted by msshd at session-establish time with
    the local host's paths (port, host-key path, banner file path,
    user-CA pubkey path).
  - ``{FROMCA_*}`` — substituted by the CA from the policy evaluation
    for this (user, server, channels, ...) tuple.

Each marker can be required or have an operator-side fallback default::

    AllowTcpForwarding {FROMCA_ALLOW_TCP_FORWARDING}        # required
    AllowTcpForwarding {FROMCA_ALLOW_TCP_FORWARDING:no}     # default "no"

Markers must match ``[A-Z][A-Z0-9_]*``. Defaults run from the colon to
the closing brace (so ``{X:a:b}`` has default "a:b"). The renderer
rejects values containing ``\\n`` / ``\\r`` for any non-multiline
marker, blocking injection through CA-supplied values.

## v1 scope

The KNOWN_FROMCA_VARIABLES schema is hardcoded. A future spec
([design/ca.md](../../../design/ca.md)) will let the CA introspect
its own schema for operator tooling (``mssh-admin template
validate``); for v1 the schema lives in this module.

## What this module is NOT

  - Not an sshd_config parser. We don't try to model sshd's full grammar;
    we just substitute markers and reject obvious injection attempts.
  - Not the template store. See ``mssh.ca.templates`` for CRUD; this
    module just consumes a template string.
  - Not the policy-evaluation layer. See ``mssh.ca.policy`` for how the
    CA decides what values to substitute; this module just substitutes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Marker schema
# ---------------------------------------------------------------------------

# Marker value shapes. Used at render time to reject CA values that wouldn't
# produce a valid sshd_config line.
SHAPE_YES_NO = 'yes_no'        # value must be "yes" or "no"
SHAPE_STRING = 'string'        # value is a single-line string (e.g. a path)
SHAPE_INTEGER = 'integer'      # value must parse as int
SHAPE_MULTILINE = 'multiline'  # value may contain \n; each line is a directive


# Markers msshd substitutes at session-establish time. The renderer treats
# these as opaque (the CA doesn't know msshd's paths), but validates that
# the template only uses recognized names.
KNOWN_LOCAL_VARIABLES: dict[str, str] = {
    'LOCAL_PORT':           'TCP port the inner sshd will bind (e.g. 49152).',
    'LOCAL_HOST_KEY':       'Path to the inner sshd host key on the msshd host.',
    'LOCAL_USER_CA_PUBKEY': 'Path to msshd\'s user-CA pubkey (TrustedUserCAKeys).',
    'LOCAL_BANNER_FILE':    'Path to the pre-auth banner file msshd wrote.',
}


# FROMCA_* markers the renderer recognizes in v1. Each entry: the variable's
# value-shape and an optional minimum OpenSSH version that supports the
# corresponding directive.
KNOWN_FROMCA_VARIABLES: dict[str, dict] = {
    'FROMCA_FORCE_COMMAND': {
        'shape': SHAPE_STRING,
        'doc': 'OpenSSH ForceCommand value. "none" disables.',
    },
    'FROMCA_ALLOW_TCP_FORWARDING': {
        'shape': SHAPE_YES_NO,
        'doc': 'OpenSSH AllowTcpForwarding directive.',
    },
    'FROMCA_X11_FORWARDING': {
        'shape': SHAPE_YES_NO,
        'doc': 'OpenSSH X11Forwarding directive.',
    },
    'FROMCA_ALLOW_AGENT_FORWARDING': {
        'shape': SHAPE_YES_NO,
        'doc': 'OpenSSH AllowAgentForwarding directive.',
    },
    'FROMCA_PERMIT_USER_ENVIRONMENT': {
        'shape': SHAPE_YES_NO,
        'doc': 'OpenSSH PermitUserEnvironment directive.',
    },
    'FROMCA_SET_ENV': {
        'shape': SHAPE_MULTILINE,
        'min_openssh_version': (7, 8),
        'doc': 'OpenSSH SetEnv lines. Multi-line; each line a "SetEnv KEY=value".',
    },
    'FROMCA_CLIENT_ALIVE_INTERVAL': {
        'shape': SHAPE_INTEGER,
        'doc': 'OpenSSH ClientAliveInterval (seconds).',
    },
    'FROMCA_CLIENT_ALIVE_COUNT_MAX': {
        'shape': SHAPE_INTEGER,
        'doc': 'OpenSSH ClientAliveCountMax (count).',
    },
}


# Regex for a single marker. Group 1 = NAME, group 2 = ":default" or None.
_MARKER_RE = re.compile(r'\{([A-Z][A-Z0-9_]*)(:[^}]*)?\}')


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

class TemplateError(ValueError):
    """Raised when a template can't be rendered or validated."""


@dataclass
class Marker:
    """One marker occurrence found in a template."""
    name: str
    has_default: bool
    default: str           # '' when has_default is False; ignored in that case

    @property
    def namespace(self) -> str:
        """Returns 'LOCAL', 'FROMCA', or '' (unknown)."""
        if self.name.startswith('LOCAL_'):
            return 'LOCAL'
        if self.name.startswith('FROMCA_'):
            return 'FROMCA'
        return ''


# ---------------------------------------------------------------------------
# Marker parsing + template validation
# ---------------------------------------------------------------------------

def parse_markers(template: str) -> list[Marker]:
    """Return every marker occurrence in the template, in source order."""
    out: list[Marker] = []
    for m in _MARKER_RE.finditer(template):
        name = m.group(1)
        default_part = m.group(2)
        if default_part is None:
            out.append(Marker(name=name, has_default=False, default=''))
        else:
            out.append(Marker(name=name, has_default=True, default=default_part[1:]))
    return out


def validate_template(template: str) -> list[str]:
    """Return a list of issues found in the template.

    Empty list = template is valid against the v1 marker schema. Each issue
    is a human-readable string; the caller decides whether to surface as
    warnings or refuse to save.
    """
    issues: list[str] = []
    for m in parse_markers(template):
        ns = m.namespace
        if ns == 'LOCAL':
            if m.name not in KNOWN_LOCAL_VARIABLES:
                issues.append(
                    f'unknown LOCAL marker {{{m.name}}}: not in '
                    f'KNOWN_LOCAL_VARIABLES'
                )
        elif ns == 'FROMCA':
            if m.name not in KNOWN_FROMCA_VARIABLES:
                issues.append(
                    f'unknown FROMCA marker {{{m.name}}}: not in '
                    f'KNOWN_FROMCA_VARIABLES'
                )
        else:
            issues.append(
                f'marker {{{m.name}}}: name must start with LOCAL_ or FROMCA_'
            )
    return issues


# ---------------------------------------------------------------------------
# Value-shape validation (injection defense)
# ---------------------------------------------------------------------------

def _check_value_shape(name: str, value: str, spec: dict) -> None:
    """Validate a value against the spec for one FROMCA marker. Raises
    TemplateError if the value would produce invalid or dangerous output."""
    shape = spec['shape']
    if shape != SHAPE_MULTILINE and '\n' in value:
        raise TemplateError(
            f'value for {{{name}}} contains newline; only allowed for '
            f'multiline markers'
        )
    if '\r' in value:
        raise TemplateError(
            f'value for {{{name}}} contains carriage return; never allowed'
        )
    if shape == SHAPE_YES_NO:
        if value not in ('yes', 'no'):
            raise TemplateError(
                f'value for {{{name}}} must be "yes" or "no", got: {value!r}'
            )
    elif shape == SHAPE_INTEGER:
        try:
            int(value)
        except ValueError:
            raise TemplateError(
                f'value for {{{name}}} must be an integer, got: {value!r}'
            )
    elif shape == SHAPE_STRING:
        # Single-line; newlines already rejected above. Don't try to fully
        # validate sshd_config quoting; that's sshd's job at parse time.
        pass
    elif shape == SHAPE_MULTILINE:
        # Each non-blank, non-comment line should look like a directive
        # (first whitespace-separated token is an identifier).
        for line in value.split('\n'):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            head = stripped.split(None, 1)[0]
            if not head or not head.replace('_', '').replace('-', '').isalnum():
                raise TemplateError(
                    f'value for {{{name}}} has line that does not start with a '
                    f'directive name: {line!r}'
                )
    else:
        raise TemplateError(
            f'internal: unknown shape {shape!r} for marker {{{name}}}'
        )


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def render(
    template: str,
    *,
    fromca_values: dict[str, str] | None = None,
    local_values: dict[str, str] | None = None,
    leave_unsubstituted: set[str] | None = None,
) -> str:
    """Substitute markers in the template.

    Args:
      template: The template text.
      fromca_values: Map of FROMCA_* marker name → value. Validated against
        ``KNOWN_FROMCA_VARIABLES``.
      local_values: Map of LOCAL_* marker name → value. Validated against
        ``KNOWN_LOCAL_VARIABLES``. msshd typically supplies these on its
        end; the CA-side render usually passes None and lets ``LOCAL_``
        prefixes pass through via ``leave_unsubstituted={'LOCAL'}``.
      leave_unsubstituted: Set of namespace prefixes ('LOCAL', 'FROMCA')
        to leave in place instead of substituting. The CA-side render
        passes {'LOCAL'} so msshd does the final pass.

    Returns: the rendered string.

    Raises: TemplateError on any unknown marker, any required marker
      without a value, any value with the wrong shape, etc.
    """
    fromca_values = fromca_values or {}
    local_values = local_values or {}
    leave = leave_unsubstituted or set()

    def sub(match: re.Match) -> str:
        name = match.group(1)
        default_part = match.group(2)
        has_default = default_part is not None
        default = default_part[1:] if has_default else ''

        ns = (
            'LOCAL' if name.startswith('LOCAL_')
            else 'FROMCA' if name.startswith('FROMCA_')
            else ''
        )

        if ns in leave:
            return match.group(0)  # leave it for the next pass

        if ns == '':
            raise TemplateError(
                f'marker {{{name}}}: name must start with LOCAL_ or FROMCA_'
            )

        # Look up the value.
        source = local_values if ns == 'LOCAL' else fromca_values
        if name in source:
            value = source[name]
        elif has_default:
            value = default
        else:
            raise TemplateError(
                f'marker {{{name}}} has no value supplied and no default'
            )

        # Validate the value's shape.
        if ns == 'LOCAL':
            if name not in KNOWN_LOCAL_VARIABLES:
                raise TemplateError(f'unknown LOCAL marker {{{name}}}')
            if '\n' in value or '\r' in value:
                raise TemplateError(
                    f'LOCAL value for {{{name}}} contains newline'
                )
        else:  # FROMCA
            spec = KNOWN_FROMCA_VARIABLES.get(name)
            if spec is None:
                raise TemplateError(f'unknown FROMCA marker {{{name}}}')
            _check_value_shape(name, value, spec)

        return value

    return _MARKER_RE.sub(sub, template)


# ---------------------------------------------------------------------------
# Policy → FROMCA values
# ---------------------------------------------------------------------------

def fromca_values_from_evaluation(eval_result) -> dict[str, str]:
    """Map a ``policy.EvaluationResult`` to a FROMCA_* substitution dict.

    Centralizes the channels / environment / force_command → sshd_config
    directive mapping. The CA calls this; msshd never sees the policy
    object.

    Channel naming convention (the CA's policy schema):
      - "session"           → required for an interactive shell or exec; not a
                              sshd_config directive itself
      - "tcp-forwarding"    → AllowTcpForwarding yes
      - "x11"               → X11Forwarding yes
      - "agent-forwarding"  → AllowAgentForwarding yes
    Absence of a channel name means the directive is "no".
    """
    channels = set(eval_result.merged_channels or [])
    env = eval_result.merged_environment or {}
    force_command = eval_result.merged_force_command

    values: dict[str, str] = {
        'FROMCA_FORCE_COMMAND': force_command if force_command else 'none',
        'FROMCA_ALLOW_TCP_FORWARDING': (
            'yes' if 'tcp-forwarding' in channels else 'no'
        ),
        'FROMCA_X11_FORWARDING': (
            'yes' if 'x11' in channels else 'no'
        ),
        'FROMCA_ALLOW_AGENT_FORWARDING': (
            'yes' if 'agent-forwarding' in channels else 'no'
        ),
        'FROMCA_PERMIT_USER_ENVIRONMENT': (
            'yes' if env else 'no'
        ),
    }
    if env:
        values['FROMCA_SET_ENV'] = '\n'.join(
            f'SetEnv {k}={v}' for k, v in sorted(env.items())
        )

    return values
