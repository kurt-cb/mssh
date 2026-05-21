# Static-test plan

How to catch the bugs documented in `design/openbugs/` (and the
closed ones in `archive/closedbugs/`) — plus the next generation of
them — **without** burning a 10-minute LXC lab cycle per attempt.
The headline insight from the rounds that produced those bug
files: five of the six bugs we found are reproducible in a plain
Python process within seconds.

## The tier we don't have today

The current test pyramid:

| Tier | What it tests | Cost | Catches |
|------|---------------|------|---------|
| 1. Unit (`tests/test_*.py`) | Individual functions in isolation. | <1s/test. Run on every save. | Logic errors inside a function. |
| 2. **MISSING** | mssh client ↔ msshd ↔ real-local-sshd round-trips. | <10s/test. Run on every commit. | **The bugs we found.** |
| 3. LXC integration (`tests/lxc/`) | Full lab on real distros, real systemd, real network. | ~10 min for setup_adhoc. | Distro / packaging / multi-host issues. |

Bug #5 (`encoding=None`) is the strongest evidence of the gap. A
Tier-2 test of the form "pipe binary data through real-msshd to
real-local-sshd, assert byte fidelity" would have caught it in 3
seconds.

## Tier-2 design

**No LXC, no containers.** Everything runs in one Linux process tree:

```
  pytest
    ├── starts a real `sshd` on a high port with a temp config + temp host key
    ├── starts msshd as a subprocess pointed at that sshd
    ├── starts a stub CA (Flask test client) that issues OpenSSH user-certs
    └── invokes the mssh client as a subprocess, asserts on stdout/stderr/exit
```

OpenSSH `sshd` already comes with every CI image. The `cryptography` lib
already mints what we need. msshd's `msshd.yaml` takes inner-host /
inner-port as config — point it at our local sshd. The CA is just a
Flask app that signs whatever we ask it to.

**Test isolation via a `tier2_lab` fixture:**

```python
@pytest.fixture
def tier2_lab(tmp_path):
    """Fresh msshd + local sshd + stub CA. Yields a small object with
    .mssh_target ('user@127.0.0.1:<port>'), .ca_url, .user_creds(), etc.
    Tears down sshd, msshd, CA on exit. ~3 seconds per fixture."""
    ...
```

Each test gets a fresh lab; tests are independent.

## Concrete tests to write first

The bugs in `design/openbugs/ + archive/closedbugs/` map 1:1 to tests:

### `test_tier2_binary_stdout.py` — regression for Bug #5

```python
def test_binary_stdout_byte_fidelity(tier2_lab):
    payload = bytes(range(256)) * 100   # every byte value
    sha_expected = hashlib.sha256(payload).hexdigest()
    sha_remote = tier2_lab.run(
        'sh', '-c',
        f'printf %s {shlex.quote(payload.hex())} | xxd -r -p | sha256sum')
    assert sha_remote.strip().startswith(sha_expected)
```

If `encoding=None` is regressed, this test fails in <2 seconds.

### `test_tier2_stdin_pipe.py` — regression for Bug #3 (data half)

```python
def test_stdin_is_forwarded(tier2_lab):
    out = tier2_lab.run('cat', stdin=b'hello via stdin\n')
    assert out == b'hello via stdin\n'

def test_stdin_eof_terminates(tier2_lab):
    """The pipe-from-parent case that hangs in production."""
    start = time.monotonic()
    tier2_lab.run('cat', stdin=b'data\n', timeout=5)
    assert time.monotonic() - start < 5  # didn't time out
```

The second test is the residual Bug #3; it'll FAIL until the protocol
gets typed EOF. **Mark it xfail until the protocol lands**, so the day
it starts passing is the day Bug #3 is closed.

### `test_tier2_exit_code.py` — regression for Bug #2

```python
def test_remote_nonzero_exit_propagates(tier2_lab):
    rc = tier2_lab.run_returncode('false')
    assert rc == 1

def test_remote_specific_exit_propagates(tier2_lab):
    rc = tier2_lab.run_returncode('sh', '-c', 'exit 42')
    assert rc == 42
```

Same xfail-until-protocol-lands pattern.

### `test_tier2_deny_message.py` — regression for Bug #1

```python
def test_unauthorized_deny_message_is_actionable(tier2_lab):
    """Stub CA returns deny; mssh client surfaces a useful message."""
    tier2_lab.ca.set_policy('alice', allow=[])
    proc = tier2_lab.run_proc('whoami')  # alice → server
    assert proc.returncode != 0
    assert b'denied' in proc.stderr.lower() or b'denied' in proc.stdout.lower()
    assert b'server closed' not in proc.stderr.lower()
```

xfail until the protocol carries deny reasons.

### `test_tier2_connect_timeout.py` — regression for Bug #6

```python
def test_connect_timeout_bounded(tier2_lab):
    """Pointing mssh at an unrouted address should fail fast."""
    start = time.monotonic()
    proc = subprocess.run(
        [str(MSSH_BIN), 'alice@192.0.2.1:2200', '--', 'whoami'],
        env=tier2_lab.user_env('alice'),
        capture_output=True, timeout=15)
    assert time.monotonic() - start < 10
    assert proc.returncode != 0
    assert b'timed out' in proc.stderr.lower() or b'unreachable' in proc.stderr.lower()
```

This one is testable today; the assertion will fail until the timeout
bug is fixed.

### `test_tier2_concurrent_sessions.py` — defensive regression

We confirmed concurrency works in the lab. A test that fires 5
parallel mssh subprocesses and asserts they all succeed protects
against future-regressions.

### `test_tier2_stderr_routing.py` — codify Bug #4 as a known limit

Today stderr is merged into stdout. That's a design decision, but
without a test, someone could "fix" it accidentally in a way that
breaks consumers. Codify the *current* behavior, with a comment
pointing to the future-ideas item for separating them.

## Coverage map — what each test prevents

| Test | Catches regression of | Catches new bug class of |
|------|----------------------|--------------------------|
| `binary_stdout` | Bug #5 specifically | Any encoding/codec drift in the byte pump |
| `stdin_pipe` (data) | Bug #3 data half | Any breakage of chan.write semantics |
| `stdin_eof` | Bug #3 EOF half (xfail) | EOF protocol design failures |
| `exit_code` | Bug #2 (xfail) | Exit-status protocol design failures |
| `deny_message` | Bug #1 (xfail) | Any "client doesn't render a server-supplied reason" |
| `connect_timeout` | Bug #6 | mssh hangs on any unreachable peer |
| `concurrent_sessions` | (nothing today) | Accidental serialization in msshd |
| `stderr_routing` | (nothing today) | Accidental change to documented merge |

## Implementation order

1. **Build `tier2_lab` fixture.** Highest-leverage single piece of
   infrastructure. ~200 lines. Once it exists, each test is 20–30
   lines.
2. **Write `binary_stdout` test.** This is the smoking gun; it
   demonstrates the value of the tier immediately.
3. **Write `concurrent_sessions` and `stderr_routing`.** These pass
   today. They lock in current good behavior.
4. **Write the four xfail tests** for the architectural bugs. They
   sit dormant until the protocol-update PR lands, at which point
   they become the "is the new protocol actually right?" gate.

## What this tier won't catch

- LXC-specific bugs: distro-version asyncssh quirks, systemd unit
  shapes, journald log capture, network bridge nuances. These still
  need Tier 3.
- Multi-host coordination: revocation across multiple msshds,
  cache propagation, CRL fan-out.
- Real-world packaging: `.deb`/`.rpm` install paths.

Tier 3 still matters. It just doesn't have to be the *only* line of
defense.

## Estimated cost / payoff

- **Fixture + 8 tests:** ~600 lines, ~1 engineering day.
- **Payoff:** every one of the bugs in design/openbugs/ + archive/closedbugs/ becomes a
  ~3-second regression check. The fixture is the foundation for
  the eventually-planned future-ideas §20 (E2E migration test), which
  also benefits from being able to spawn parts of the system without
  full LXC.
