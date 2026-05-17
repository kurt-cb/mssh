# adhoc-lab ansible project

A small ansible project that gets rendered into the running mssh
adhoc lab. The test harness (`test_setup_only_msshd.py`) copies this
directory into both:

  - `<invocation_cwd>/ansible-project/` on the host
  - `/root/ansible-project/` on the CA container

and pushes the private key + populated `hosts.ini` into both copies.
You can run ansible from either side identically.

## Layout

| File                       | Purpose                                          |
|----------------------------|--------------------------------------------------|
| `ansible.cfg`              | Inventory, host-key-check off, pipelining        |
| `hosts.ini`                | Inventory; **rendered fresh** by the test harness |
| `site.yml`                 | Top-level playbook; pulls in every `task*.yml`   |
| `variables.yml`            | Proxy IP/port + deployment values                |
| `task_squid.yml`           | Point each host at the squid proxy (tag: squid)  |
| `task_upgrade_asyncssh.yml`| Fix Ubuntu 22.04 asyncssh ≤2.5 bug (tag: upgrade_asyncssh) |
| `ansible_id_ed25519`       | Private key — generated at lab-setup time        |

## Invocation

**Task files (`task_*.yml`) are NOT standalone playbooks.** They're
task lists that `site.yml` pulls in via `include_tasks`. Running
them directly fails with `'ansible.builtin.lineinfile' is not a
valid attribute for a Play`.

Always invoke through `site.yml`:

```sh
cd ansible-project              # or /root/ansible-project on the CA

ansible all -m ping             # smoke-test connectivity
ansible-playbook site.yml       # run every task on proxy_clients

# Subset by tag (cleaner than --limit):
ansible-playbook site.yml --tags squid
ansible-playbook site.yml --tags upgrade_asyncssh

# Subset by host group:
ansible-playbook site.yml --limit ubuntu_servers
```

`proxy_clients` is a `children` group rolling up
`ubuntu_servers + alpine_servers + debian + fedora_servers`, so
`ansible-playbook site.yml` hits every lab container by default.

## Adding tasks

Drop a new `task_<name>.yml` here. `site.yml`'s glob picks it up
automatically on the next run. Tag your tasks so operators can run
them selectively:

```yaml
- name: "myfeature: do the thing"
  ansible.builtin.command: /usr/local/bin/thing
  tags: [myfeature]
```

Then: `ansible-playbook site.yml --tags myfeature`.

## Re-rendering

The harness deletes `/root/ansible-project/` and re-pushes from the
host on every lab re-setup, so any edits you make on the CA are
**lost on the next test run**. Edit files in the host-side copy
(under `python/ansible-project/` at the repo root, or wherever you
ran the test from) and re-push, or commit changes back to
`python/tests/ansible-project/` for permanence.
