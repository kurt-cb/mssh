"""Variables for every host — equivalent to ansible-project/variables.yml.

pyinfra auto-loads ``group_data/all.py`` and exposes the values to
deploys via ``host.data.<name>``. ``group_data/<group>.py`` would
override these per group, but the lab keeps everything at "all" for
parity with the ansible setup.
"""

# Proxy Settings
proxy_ip = "10.26.244.2"
proxy_hostname = "squid-proxy.local"
proxy_port = "3128"

# Web Server Settings
web_port = 80

# Database Settings
db_name = "production_db"
