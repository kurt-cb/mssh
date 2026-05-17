"""Unit tests for mssh.ca.templates — the template store + resolver."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mssh.ca.enrollment import Enrollment, EnrollmentError
from mssh.ca.templates import (
    BUILTIN_OPENSSH_TEMPLATE,
    BUILTIN_TEMPLATES,
    SOURCE_BUILTIN,
    SOURCE_DEFAULT,
    SOURCE_GROUP,
    SOURCE_SERVER,
    get_effective_template,
    list_templates,
    set_default_template,
    set_group_template,
    set_server_template,
    unset_default_template,
    unset_group_template,
    unset_server_template,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def enrollment(tmp_path):
    e = Enrollment(tmp_path / 'enrollment.yaml')
    # Enrol one server in a couple of groups so resolver tests have material.
    e.add_server('srv-acct', 'CN=srv-acct', groups=['accounting', 'production'])
    return e


# ---------------------------------------------------------------------------
# Resolver precedence
# ---------------------------------------------------------------------------


def test_resolver_falls_back_to_builtin_when_nothing_set(enrollment):
    tpl, source, detail = get_effective_template(enrollment, 'srv-acct')
    assert tpl == BUILTIN_OPENSSH_TEMPLATE
    assert source == SOURCE_BUILTIN
    assert detail is None


def test_resolver_uses_fleet_default_when_set(enrollment):
    set_default_template(enrollment, 'openssh', '# fleet default content')
    tpl, source, detail = get_effective_template(enrollment, 'srv-acct')
    assert tpl == '# fleet default content'
    assert source == SOURCE_DEFAULT


def test_resolver_prefers_group_over_fleet_default(enrollment):
    set_default_template(enrollment, 'openssh', '# fleet default')
    set_group_template(enrollment, 'accounting', 'openssh', '# accounting group')
    tpl, source, detail = get_effective_template(enrollment, 'srv-acct')
    assert tpl == '# accounting group'
    assert source == SOURCE_GROUP
    assert detail == 'accounting'


def test_resolver_walks_groups_in_server_order(enrollment):
    """A server's groups attribute is a list in declaration order; resolver
    picks the first group that has a template."""
    # srv-acct's groups are ['accounting', 'production']; set the template
    # only on 'production' to verify the resolver walks past 'accounting'.
    set_group_template(enrollment, 'production', 'openssh', '# production')
    tpl, source, detail = get_effective_template(enrollment, 'srv-acct')
    assert tpl == '# production'
    assert source == SOURCE_GROUP
    assert detail == 'production'


def test_resolver_prefers_server_over_group(enrollment):
    set_group_template(enrollment, 'accounting', 'openssh', '# group')
    set_server_template(enrollment, 'srv-acct', 'openssh', '# server')
    tpl, source, detail = get_effective_template(enrollment, 'srv-acct')
    assert tpl == '# server'
    assert source == SOURCE_SERVER
    assert detail == 'srv-acct'


def test_resolver_no_server_falls_through_to_default(enrollment):
    """Caller asks for the effective template with server_name=None
    (e.g., 'mssh-admin template show' against the fleet-default)."""
    set_default_template(enrollment, 'openssh', '# default')
    tpl, source, detail = get_effective_template(enrollment, None)
    assert tpl == '# default'
    assert source == SOURCE_DEFAULT


def test_resolver_unknown_server_falls_back_to_default(enrollment):
    """Asking about a server that isn't enrolled returns default (or
    built-in). The resolver doesn't error — it falls back."""
    set_default_template(enrollment, 'openssh', '# default')
    tpl, source, _ = get_effective_template(enrollment, 'unknown-host')
    assert tpl == '# default'
    assert source == SOURCE_DEFAULT


def test_resolver_unknown_kind_raises(enrollment):
    with pytest.raises(EnrollmentError, match='no built-in template'):
        get_effective_template(enrollment, 'srv-acct', kind='dropbear')


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def test_set_default_persists(enrollment, tmp_path):
    set_default_template(enrollment, 'openssh', '# from disk')
    # Reload from disk
    e2 = Enrollment(tmp_path / 'enrollment.yaml')
    assert e2.templates_default.get('openssh') == '# from disk'


def test_unset_default_reverts_to_builtin(enrollment):
    set_default_template(enrollment, 'openssh', '# custom')
    unset_default_template(enrollment, 'openssh')
    tpl, source, _ = get_effective_template(enrollment, 'srv-acct')
    assert source == SOURCE_BUILTIN
    assert tpl == BUILTIN_OPENSSH_TEMPLATE


def test_set_group_persists(enrollment, tmp_path):
    set_group_template(enrollment, 'accounting', 'openssh', '# acct')
    e2 = Enrollment(tmp_path / 'enrollment.yaml')
    assert e2.templates_groups.get('accounting', {}).get('openssh') == '# acct'


def test_unset_group_collapses_empty_dict(enrollment):
    set_group_template(enrollment, 'accounting', 'openssh', '# x')
    unset_group_template(enrollment, 'accounting', 'openssh')
    # The group entry should be cleaned up entirely.
    assert 'accounting' not in enrollment.templates_groups


def test_set_server_template_requires_enrolled_server(enrollment):
    with pytest.raises(EnrollmentError, match='not enrolled'):
        set_server_template(enrollment, 'no-such-server', 'openssh', '# x')


def test_set_server_template_persists(enrollment, tmp_path):
    set_server_template(enrollment, 'srv-acct', 'openssh', '# srv-acct')
    e2 = Enrollment(tmp_path / 'enrollment.yaml')
    assert (
        e2.templates_servers.get('srv-acct', {}).get('openssh')
        == '# srv-acct'
    )


def test_removing_server_drops_its_template(enrollment, tmp_path):
    set_server_template(enrollment, 'srv-acct', 'openssh', '# srv-acct')
    enrollment.remove_server('srv-acct')
    e2 = Enrollment(tmp_path / 'enrollment.yaml')
    assert 'srv-acct' not in e2.templates_servers


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def test_unknown_kind_in_set_default_rejected(enrollment):
    with pytest.raises(EnrollmentError, match='unknown inner_sshd_kind'):
        set_default_template(enrollment, 'dropbear', '# nope')


def test_unknown_kind_in_set_server_rejected(enrollment):
    with pytest.raises(EnrollmentError, match='unknown inner_sshd_kind'):
        set_server_template(enrollment, 'srv-acct', 'dropbear', '# nope')


# ---------------------------------------------------------------------------
# list_templates
# ---------------------------------------------------------------------------


def test_list_templates_includes_all_layers(enrollment):
    set_default_template(enrollment, 'openssh', '# default')
    set_group_template(enrollment, 'accounting', 'openssh', '# group')
    set_server_template(enrollment, 'srv-acct', 'openssh', '# server')
    snapshot = list_templates(enrollment)
    assert snapshot['builtin']['openssh'] == BUILTIN_OPENSSH_TEMPLATE
    assert snapshot['default']['openssh'] == '# default'
    assert snapshot['groups']['accounting']['openssh'] == '# group'
    assert snapshot['servers']['srv-acct']['openssh'] == '# server'


def test_list_templates_empty_when_nothing_set(enrollment):
    snapshot = list_templates(enrollment)
    assert snapshot['default'] == {}
    assert snapshot['groups'] == {}
    assert snapshot['servers'] == {}
    # Built-in always present.
    assert snapshot['builtin'] == BUILTIN_TEMPLATES


# ---------------------------------------------------------------------------
# YAML round-trip
# ---------------------------------------------------------------------------


def test_enrollment_yaml_has_templates_section(enrollment, tmp_path):
    set_default_template(enrollment, 'openssh', '# d')
    set_group_template(enrollment, 'accounting', 'openssh', '# g')
    set_server_template(enrollment, 'srv-acct', 'openssh', '# s')
    raw = yaml.safe_load((tmp_path / 'enrollment.yaml').read_text())
    tpls = raw['templates']
    assert tpls['default']['openssh'] == '# d'
    assert tpls['groups']['accounting']['openssh'] == '# g'
    assert tpls['servers']['srv-acct']['openssh'] == '# s'


def test_loading_pre_templates_enrollment_works(tmp_path):
    """An enrollment.yaml written by a previous-release CA (no `templates:`
    section) must load without error and resolve to the built-in."""
    yaml_text = (
        'servers:\n'
        '  srv-acct:\n'
        '    mtls_subject: CN=srv-acct\n'
        '    groups: [accounting]\n'
        '    enrolled_at: \'\'\n'
        '    enrolled_by: \'\'\n'
    )
    path = tmp_path / 'enrollment.yaml'
    path.write_text(yaml_text)
    e = Enrollment(path)
    assert e.templates_default == {}
    assert e.templates_groups == {}
    assert e.templates_servers == {}
    tpl, source, _ = get_effective_template(e, 'srv-acct')
    assert source == SOURCE_BUILTIN
