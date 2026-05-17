"""Unit tests for the per-server banner template rendering in
``mssh.msshd.inner._render_banner``."""
from __future__ import annotations

from pathlib import Path

import pytest

from mssh.msshd.inner import _DEFAULT_BANNER, _render_banner


def test_empty_template_path_returns_default():
    assert _render_banner('', {}) == _DEFAULT_BANNER


def test_missing_file_returns_default(tmp_path, caplog):
    missing = tmp_path / 'nope.txt'
    with caplog.at_level('WARNING'):
        out = _render_banner(str(missing), {'server': 'x'})
    assert out == _DEFAULT_BANNER
    assert 'unreadable' in caplog.text


def test_basic_substitution(tmp_path):
    tpl = tmp_path / 'banner.txt'
    tpl.write_text('Welcome to {server}, owned by {group}.\n')
    out = _render_banner(str(tpl),
                         {'server': 'srv-acct', 'group': 'accounting'})
    assert out == 'Welcome to srv-acct, owned by accounting.\n'


def test_missing_token_left_literal(tmp_path):
    """A typo in the template must NOT crash msshd startup."""
    tpl = tmp_path / 'banner.txt'
    tpl.write_text('Server: {server}, Owner: {missing_key}.\n')
    out = _render_banner(str(tpl), {'server': 'srv-acct'})
    assert out == 'Server: srv-acct, Owner: {missing_key}.\n'


def test_malformed_template_falls_back(tmp_path, caplog):
    tpl = tmp_path / 'banner.txt'
    # Stray '{' triggers a ValueError in format_map.
    tpl.write_text('Welcome to {server.\n')
    with caplog.at_level('WARNING'):
        out = _render_banner(str(tpl), {'server': 'x'})
    assert out == _DEFAULT_BANNER
    assert 'formatting error' in caplog.text


def test_unicode_passthrough(tmp_path):
    """Templates frequently contain box-drawing / emoji; verify pass-through."""
    tpl = tmp_path / 'banner.txt'
    tpl.write_text('─── {server} ───\n')
    out = _render_banner(str(tpl), {'server': 'srv'})
    assert out == '─── srv ───\n'
