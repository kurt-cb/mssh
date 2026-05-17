"""Unit + property tests for mssh.ca.render."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from mssh.ca.render import (
    KNOWN_FROMCA_VARIABLES,
    KNOWN_LOCAL_VARIABLES,
    Marker,
    TemplateError,
    fromca_values_from_evaluation,
    parse_markers,
    render,
    validate_template,
)


# ---------------------------------------------------------------------------
# Marker parsing
# ---------------------------------------------------------------------------


def test_parse_markers_handles_required_and_default_forms():
    tpl = (
        'A {FOO} B {BAR:default} C\n'
        '{BAZ}\n'
        'no markers here\n'
        '{QUX:has:colon:in:default} end\n'
    )
    markers = parse_markers(tpl)
    assert [(m.name, m.has_default, m.default) for m in markers] == [
        ('FOO', False, ''),
        ('BAR', True, 'default'),
        ('BAZ', False, ''),
        ('QUX', True, 'has:colon:in:default'),
    ]


def test_parse_markers_skips_non_uppercase():
    """A pattern like {foo} or {Foo} doesn't match — markers are
    ALL_CAPS by convention to avoid colliding with comments / strings
    that happen to use braces."""
    tpl = '{foo} {Foo} {BAR_OK}'
    markers = parse_markers(tpl)
    assert [m.name for m in markers] == ['BAR_OK']


def test_marker_namespace():
    assert Marker('LOCAL_PORT', False, '').namespace == 'LOCAL'
    assert Marker('FROMCA_X', False, '').namespace == 'FROMCA'
    assert Marker('OTHER', False, '').namespace == ''


# ---------------------------------------------------------------------------
# validate_template
# ---------------------------------------------------------------------------


def test_validate_template_passes_known_markers():
    tpl = (
        'Port {LOCAL_PORT}\n'
        'AllowTcpForwarding {FROMCA_ALLOW_TCP_FORWARDING:no}\n'
    )
    assert validate_template(tpl) == []


def test_validate_template_flags_unknown_local():
    issues = validate_template('Port {LOCAL_PORT}\nHostKey {LOCAL_BOGUS}')
    assert len(issues) == 1
    assert 'LOCAL_BOGUS' in issues[0]


def test_validate_template_flags_unknown_fromca():
    issues = validate_template('Foo {FROMCA_DOES_NOT_EXIST}')
    assert len(issues) == 1
    assert 'FROMCA_DOES_NOT_EXIST' in issues[0]


def test_validate_template_flags_unnamespaced_marker():
    issues = validate_template('Foo {SOME_RANDOM_MARKER}')
    assert len(issues) == 1
    assert 'SOME_RANDOM_MARKER' in issues[0]
    assert 'LOCAL_ or FROMCA_' in issues[0]


# ---------------------------------------------------------------------------
# render — basic substitution
# ---------------------------------------------------------------------------


def test_render_substitutes_known_values():
    tpl = 'Port {LOCAL_PORT}\nForceCommand {FROMCA_FORCE_COMMAND}\n'
    out = render(
        tpl,
        fromca_values={'FROMCA_FORCE_COMMAND': '/bin/db-shell'},
        local_values={'LOCAL_PORT': '49152'},
    )
    assert out == 'Port 49152\nForceCommand /bin/db-shell\n'


def test_render_uses_default_when_value_missing():
    tpl = 'AllowTcpForwarding {FROMCA_ALLOW_TCP_FORWARDING:no}\n'
    out = render(tpl, fromca_values={}, local_values={})
    assert out == 'AllowTcpForwarding no\n'


def test_render_raises_on_missing_required_marker():
    tpl = 'ForceCommand {FROMCA_FORCE_COMMAND}\n'
    with pytest.raises(TemplateError, match='no value supplied'):
        render(tpl, fromca_values={}, local_values={})


def test_render_raises_on_unknown_local_marker():
    tpl = 'Foo {LOCAL_BOGUS}\n'
    with pytest.raises(TemplateError, match='unknown LOCAL marker'):
        render(tpl, fromca_values={}, local_values={'LOCAL_BOGUS': 'x'})


def test_render_raises_on_unknown_fromca_marker():
    tpl = 'Foo {FROMCA_BOGUS}\n'
    with pytest.raises(TemplateError, match='unknown FROMCA marker'):
        render(tpl, fromca_values={'FROMCA_BOGUS': 'x'}, local_values={})


def test_render_raises_on_unnamespaced_marker():
    tpl = 'Foo {BARE}\n'
    with pytest.raises(TemplateError, match='start with LOCAL_ or FROMCA_'):
        render(tpl, fromca_values={}, local_values={})


# ---------------------------------------------------------------------------
# render — injection defense
# ---------------------------------------------------------------------------


def test_render_rejects_newline_in_yes_no():
    tpl = 'AllowTcpForwarding {FROMCA_ALLOW_TCP_FORWARDING}\n'
    with pytest.raises(TemplateError, match='newline'):
        render(
            tpl,
            fromca_values={'FROMCA_ALLOW_TCP_FORWARDING': 'no\nPermitRootLogin yes'},
            local_values={},
        )


def test_render_rejects_carriage_return_everywhere():
    tpl = 'ForceCommand {FROMCA_FORCE_COMMAND}\n'
    with pytest.raises(TemplateError, match='carriage return'):
        render(
            tpl,
            fromca_values={'FROMCA_FORCE_COMMAND': 'foo\rPermitRootLogin yes'},
            local_values={},
        )


def test_render_rejects_newline_in_local_value():
    tpl = 'Port {LOCAL_PORT}\n'
    with pytest.raises(TemplateError, match='newline'):
        render(
            tpl,
            fromca_values={},
            local_values={'LOCAL_PORT': '49152\nPermitRootLogin yes'},
        )


def test_render_yes_no_rejects_arbitrary_string():
    tpl = 'AllowTcpForwarding {FROMCA_ALLOW_TCP_FORWARDING}\n'
    with pytest.raises(TemplateError, match='must be "yes" or "no"'):
        render(
            tpl,
            fromca_values={'FROMCA_ALLOW_TCP_FORWARDING': 'maybe'},
            local_values={},
        )


def test_render_integer_rejects_non_integer():
    tpl = 'ClientAliveInterval {FROMCA_CLIENT_ALIVE_INTERVAL}\n'
    with pytest.raises(TemplateError, match='integer'):
        render(
            tpl,
            fromca_values={'FROMCA_CLIENT_ALIVE_INTERVAL': 'forever'},
            local_values={},
        )


def test_render_multiline_accepts_newlines():
    tpl = '{FROMCA_SET_ENV:}\n'
    out = render(
        tpl,
        fromca_values={'FROMCA_SET_ENV': 'SetEnv FOO=bar\nSetEnv BAZ=qux'},
        local_values={},
    )
    assert 'SetEnv FOO=bar' in out
    assert 'SetEnv BAZ=qux' in out


def test_render_multiline_rejects_lines_without_directive():
    tpl = '{FROMCA_SET_ENV:}\n'
    with pytest.raises(TemplateError, match='does not start with a directive'):
        render(
            tpl,
            fromca_values={'FROMCA_SET_ENV': '!!! not a directive'},
            local_values={},
        )


def test_render_multiline_allows_blank_and_comment_lines():
    tpl = '{FROMCA_SET_ENV:}\n'
    out = render(
        tpl,
        fromca_values={'FROMCA_SET_ENV': '# a comment\n\nSetEnv FOO=bar'},
        local_values={},
    )
    assert 'SetEnv FOO=bar' in out


# ---------------------------------------------------------------------------
# render — leave_unsubstituted (CA-side then msshd-side pass)
# ---------------------------------------------------------------------------


def test_render_leaves_local_namespace_alone_when_requested():
    tpl = (
        'Port {LOCAL_PORT}\n'
        'AllowTcpForwarding {FROMCA_ALLOW_TCP_FORWARDING:no}\n'
    )
    out = render(
        tpl,
        fromca_values={'FROMCA_ALLOW_TCP_FORWARDING': 'yes'},
        local_values={},
        leave_unsubstituted={'LOCAL'},
    )
    assert 'Port {LOCAL_PORT}' in out
    assert 'AllowTcpForwarding yes' in out


def test_render_two_pass_workflow():
    """The CA-side render leaves LOCAL_*; msshd's pass fills them in."""
    tpl = (
        'Port {LOCAL_PORT}\n'
        'ForceCommand {FROMCA_FORCE_COMMAND}\n'
    )
    ca_rendered = render(
        tpl,
        fromca_values={'FROMCA_FORCE_COMMAND': 'none'},
        leave_unsubstituted={'LOCAL'},
    )
    # Now the msshd-side pass.
    final = render(
        ca_rendered,
        local_values={'LOCAL_PORT': '49152'},
    )
    assert final == 'Port 49152\nForceCommand none\n'


# ---------------------------------------------------------------------------
# fromca_values_from_evaluation
# ---------------------------------------------------------------------------


@dataclass
class _MockEval:
    """Minimal stand-in for ``mssh.ca.policy.EvaluationResult`` so we can
    test the mapping without dragging in the full policy module."""
    merged_channels: list[str]
    merged_environment: dict[str, str]
    merged_force_command: str | None


def test_eval_mapping_basics():
    e = _MockEval(
        merged_channels=['session'],
        merged_environment={},
        merged_force_command=None,
    )
    v = fromca_values_from_evaluation(e)
    assert v['FROMCA_FORCE_COMMAND'] == 'none'
    assert v['FROMCA_ALLOW_TCP_FORWARDING'] == 'no'
    assert v['FROMCA_X11_FORWARDING'] == 'no'
    assert v['FROMCA_ALLOW_AGENT_FORWARDING'] == 'no'
    assert v['FROMCA_PERMIT_USER_ENVIRONMENT'] == 'no'
    assert 'FROMCA_SET_ENV' not in v


def test_eval_mapping_channels_enable_forwarding():
    e = _MockEval(
        merged_channels=['session', 'tcp-forwarding', 'x11'],
        merged_environment={},
        merged_force_command=None,
    )
    v = fromca_values_from_evaluation(e)
    assert v['FROMCA_ALLOW_TCP_FORWARDING'] == 'yes'
    assert v['FROMCA_X11_FORWARDING'] == 'yes'
    assert v['FROMCA_ALLOW_AGENT_FORWARDING'] == 'no'


def test_eval_mapping_force_command_preserved():
    e = _MockEval(
        merged_channels=['session'],
        merged_environment={},
        merged_force_command='/usr/local/bin/dbshell',
    )
    v = fromca_values_from_evaluation(e)
    assert v['FROMCA_FORCE_COMMAND'] == '/usr/local/bin/dbshell'


def test_eval_mapping_environment_emits_set_env():
    e = _MockEval(
        merged_channels=['session'],
        merged_environment={'LANG': 'en_US.UTF-8', 'EDITOR': 'vim'},
        merged_force_command=None,
    )
    v = fromca_values_from_evaluation(e)
    assert v['FROMCA_PERMIT_USER_ENVIRONMENT'] == 'yes'
    # Sorted by key for determinism
    assert v['FROMCA_SET_ENV'] == 'SetEnv EDITOR=vim\nSetEnv LANG=en_US.UTF-8'


# ---------------------------------------------------------------------------
# End-to-end: realistic template
# ---------------------------------------------------------------------------


def test_full_template_renders():
    tpl = (
        '# msshd hermetic config\n'
        'Port              {LOCAL_PORT}\n'
        'HostKey           {LOCAL_HOST_KEY}\n'
        'TrustedUserCAKeys {LOCAL_USER_CA_PUBKEY}\n'
        'Banner            {LOCAL_BANNER_FILE}\n'
        '\n'
        'PermitRootLogin       no\n'
        'PasswordAuthentication no\n'
        'AuthenticationMethods publickey\n'
        '\n'
        'ForceCommand          {FROMCA_FORCE_COMMAND:none}\n'
        'AllowTcpForwarding    {FROMCA_ALLOW_TCP_FORWARDING:no}\n'
        'X11Forwarding         {FROMCA_X11_FORWARDING:no}\n'
        'AllowAgentForwarding  {FROMCA_ALLOW_AGENT_FORWARDING:no}\n'
        'PermitUserEnvironment {FROMCA_PERMIT_USER_ENVIRONMENT:no}\n'
    )

    e = _MockEval(
        merged_channels=['session', 'tcp-forwarding'],
        merged_environment={},
        merged_force_command=None,
    )
    fromca = fromca_values_from_evaluation(e)
    local = {
        'LOCAL_PORT': '49152',
        'LOCAL_HOST_KEY': '/var/lib/mssh/inner-sshd/host_key',
        'LOCAL_USER_CA_PUBKEY': '/var/lib/mssh/inner-sshd/user-ca.pub',
        'LOCAL_BANNER_FILE': '/var/lib/mssh/inner-sshd/banner',
    }
    out = render(tpl, fromca_values=fromca, local_values=local)
    assert 'Port              49152' in out
    assert 'ForceCommand          none' in out
    assert 'AllowTcpForwarding    yes' in out
    assert 'X11Forwarding         no' in out
    # No leftover markers
    assert '{LOCAL_' not in out
    assert '{FROMCA_' not in out


def test_full_template_two_pass_yields_same_result():
    """Render CA-side (with leave_unsubstituted={'LOCAL'}), then msshd-side.
    Should produce the same final output as a one-pass render."""
    tpl = (
        'Port              {LOCAL_PORT}\n'
        'ForceCommand      {FROMCA_FORCE_COMMAND:none}\n'
    )
    fromca = {'FROMCA_FORCE_COMMAND': 'none'}
    local = {'LOCAL_PORT': '49152'}

    one_pass = render(tpl, fromca_values=fromca, local_values=local)
    ca_pass = render(tpl, fromca_values=fromca, leave_unsubstituted={'LOCAL'})
    msshd_pass = render(ca_pass, local_values=local)
    assert one_pass == msshd_pass


# ---------------------------------------------------------------------------
# Schema sanity (catches drift between schema dicts and tests)
# ---------------------------------------------------------------------------


def test_every_known_fromca_has_shape():
    """Every entry in KNOWN_FROMCA_VARIABLES must declare a shape."""
    for name, spec in KNOWN_FROMCA_VARIABLES.items():
        assert 'shape' in spec, f'{name} missing shape'
        assert 'doc' in spec, f'{name} missing doc'


def test_every_known_local_has_doc():
    """Every entry in KNOWN_LOCAL_VARIABLES is a name → doc string."""
    for name, doc in KNOWN_LOCAL_VARIABLES.items():
        assert isinstance(doc, str) and doc, f'{name} missing or empty doc'
