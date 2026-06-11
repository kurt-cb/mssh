# mssh-admin-web — browser portal

**Design reference:** [design §11 mssh-admin-web](../design/mssh_design_v1.md#11--module-mssh-admin-web-).

Optional browser portal over the mssh-ca admin API. Disabled by
default; deploy alongside mssh-ca behind apache2.

Same actions as `mssh-admin` (§7); same role checks; same audit
trail. **It does not introduce new admin operations** — it dispatches
to the same `/v1/admin/*` endpoints the CLI uses.

---

## When to deploy it

- You have admins who prefer a browser to a CLI.
- You want a read-only dashboard for at-a-glance fleet status.
- You have a small operator team and value the UX over the CLI's
  scriptability.

If you're comfortable with `mssh-admin` from the terminal, you don't
need this.

---

## Deploy

```sh
# 1. Install (system pkg)
sudo apt install mssh-admin-web

# 2. Mint an admin mTLS cert for this web instance (an `admin` or
#    `superuser` role per design §14.1.2 RBAC; it operates on behalf
#    of users who authenticate via apache2):
mssh-admin admin add admin-web --role admin
# Capture cert + key.

# 3. Install /etc/mssh-admin-web/config.yaml (see design §14.3.5)

# 4. Configure apache2 reverse proxy + mTLS termination
#    (forwards X-Client-CN; sketch in design §15.8)

# 5. Start
sudo systemctl enable --now mssh-admin-web
```

---

## Recommended: mssh-tunneled localhost (v1 target 🚧)

**Don't expose mssh-admin-web on the public internet.** Instead,
run it on localhost on the mssh-ca host and reach it via:

```sh
mssh -L 9443:localhost:9443 mssh-ca-host
# Then open https://localhost:9443/ in a browser.
```

This composes the admin web's access bar with mssh's auth bar —
no extra internet attack surface.

The `-L` flag is 🚧 a v1 target (§6.3.5). Until it lands, deploy
mssh-admin-web behind apache2 with the recommended hardening below.

---

## v1 surface

- **§11.3.1 Read-only views** ✅ — dashboards, lists, audit search.
- **§11.3.2 mTLS re-issue endpoint** ✅ — operator's own cert renewal.
- **§11.3.3 Mutating CRUD** 🚧 v1 ship blocker — admin actions
  through the web UI (CLI-only today).
- **§11.3.4 Auth model** ✅ — mTLS at apache2; CA admin role check
  on every request.
- **§11.3.5 mssh-tunneled localhost** 🚧 — depends on §6.3.5 mssh
  `-L`.

Design: [§11.3 implementation](../design/mssh_design_v1.md#113--implementation).

---

## Related docs

- [docs/4-mssh-ca.md](4-mssh-ca.md) — the CA you're talking to
- [docs/7-mssh-admin.md](7-mssh-admin.md) — the CLI equivalent
- [docs/15-third-party-integration.md](15-third-party-integration.md) — apache2 frontend pattern (§15.8)
