"""Top-level deploy — pyinfra equivalent of site.yml.

Mirrors site.yml's glob behavior: every ``task_*.py`` and
``framework_*.py`` sibling is pulled in, in lexical order. Drop a new
task_<name>.py here and the next run picks it up automatically.

Usage:

    pyinfra inventory.py deploy.py                 # every task on every host
    pyinfra inventory.py:ubuntu_servers deploy.py  # subset by group
    pyinfra inventory.py task_squid.py             # just one task

There is no direct equivalent of ansible's ``--tags`` because each
task is already its own runnable file — invoke whichever you want.
"""

from pathlib import Path

from pyinfra.operations import server

_HERE = Path(__file__).parent

_tasks = sorted(_HERE.glob("task_*.py")) + sorted(_HERE.glob("framework_*.py"))

for _task in _tasks:
    # pyinfra's local.include() lets a deploy chain other deploy files
    # in-place. Import here to keep the top of the module clean and to
    # surface a clear error if pyinfra isn't installed.
    from pyinfra.operations import local
    local.include(str(_task.relative_to(_HERE)))
