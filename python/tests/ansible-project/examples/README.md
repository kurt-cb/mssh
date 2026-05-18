# Spinup Examples

These examples show how to use the `lxc_spinup` role to create and configure containers for different services.

## Using the Role

The `lxc_spinup` role handles:
- Creating an LXC container from an image
- Installing and configuring SSH
- Adding the new host to the Ansible inventory
- Waiting for SSH to be ready

Then your playbook can configure the service on the new host.

## Examples

### Spinup Squid Proxy
```bash
ansible-playbook examples/spinup_squid.yml
```

This creates a `squid-proxy` container and configures it with Squid.

### Spinup Nginx Web Server
```bash
ansible-playbook examples/spinup_nginx.yml
```

This creates a `web-server` container and configures it with Nginx.

## Creating Your Own Spinup Playbook

Use the structure from `spinup_squid.yml` or `spinup_nginx.yml`:

```yaml
---
- name: Spinup Your Service
  hosts: localhost
  gather_facts: no
  roles:
    - role: lxc_spinup
      vars:
        container_name: my-service
        image_name: mssh-alpine-fixed
        ssh_key_path: ./ansible_id_ed25519

- name: Configure Your Service
  hosts: my-service
  become: yes
  gather_facts: yes

  tasks:
    # Your service configuration here
    - name: Install my-service
      ansible.builtin.package:
        name: my-service
        state: present
```

## Role Variables

Available variables in `lxc_spinup`:

| Variable | Default | Description |
|----------|---------|-------------|
| `container_name` | (required) | Name of the LXC container |
| `image_name` | mssh-alpine-fixed | Image to launch from |
| `container_user` | root | User for SSH access |
| `ssh_key_path` | ./ansible_id_ed25519 | SSH private key location |
| `wait_timeout` | 30 | Timeout for SSH ready (seconds) |

## Notes

- The role adds newly created hosts to the `spinned_up_hosts` group
- Make sure your SSH keys exist before running
- The container must have network access to be added to inventory
