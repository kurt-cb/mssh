"""Bug #5 regression — msshd's create_session() must pass encoding=None.

If asyncssh's default UTF-8 codec is left in place on the SSH channel,
any non-UTF-8 byte from the remote command's stdout silently aborts
the channel (zero-byte output from the user's perspective). The fix
is one kwarg: `encoding=None` on `conn.create_session(...)`.

A full integration test would spawn a real local sshd + msshd + stub
CA, send `bytes(range(256))` through, and verify byte-for-byte
fidelity. That fixture is its own multi-hundred-LOC effort (see
design/static-test-plan.md Tier-2). Until that exists, this unit-level
test asserts the SPECIFIC ARGUMENT msshd passes — which is what would
have caught Bug #5 at PR time.

If someone removes `encoding=None` for any reason, this test fails
loudly with a pointer to the bug.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest


def _ssh_proxy_path() -> Path:
    return (Path(__file__).resolve().parents[2]
            / 'python' / 'packages' / 'msshd' / 'src' / 'mssh' / 'msshd'
            / 'ssh_proxy.py')


def _find_create_session_call(tree: ast.AST) -> ast.Call | None:
    """Walk the AST looking for the `conn.create_session(...)` call in
    ssh_proxy.py. Returns the Call node (so the test can inspect its
    kwargs)."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Match `conn.create_session(...)` or `<anything>.create_session(...)`.
        if isinstance(func, ast.Attribute) and func.attr == 'create_session':
            return node
    return None


def test_ssh_proxy_passes_encoding_none_to_create_session():
    """msshd's create_session call MUST have encoding=None as a kwarg.

    AST-walking the source rather than monkeypatching asyncssh because:
    (1) it's faster, (2) it survives upgrade of the asyncssh library,
    (3) it makes the test specific to the regression we want to catch.
    """
    path = _ssh_proxy_path()
    assert path.exists(), f'ssh_proxy.py not at expected path: {path}'

    tree = ast.parse(path.read_text())
    call = _find_create_session_call(tree)
    assert call is not None, (
        f'no conn.create_session(...) call found in {path}; '
        f'msshd was supposed to drive the inner sshd over asyncssh — '
        f'has this been refactored?')

    encoding_arg = next((kw for kw in call.keywords
                         if kw.arg == 'encoding'), None)
    assert encoding_arg is not None, (
        'create_session() in ssh_proxy.py is missing the `encoding` '
        'kwarg. Without `encoding=None`, asyncssh runs the channel in '
        'utf-8 string mode and silently drops any non-UTF-8 byte. '
        'This is Bug #5. See adhoc-bugs.md.')

    # Must be the literal None.
    val = encoding_arg.value
    if not (isinstance(val, ast.Constant) and val.value is None):
        pytest.fail(
            'create_session() must use `encoding=None`. The current '
            f'value parses as {ast.unparse(val)!r}. The whole point '
            'of the fix is to put the channel in byte-mode; any other '
            'value will leave us back at Bug #5.'
        )
