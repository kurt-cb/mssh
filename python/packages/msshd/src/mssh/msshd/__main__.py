"""Entry point: ``python -m mssh.msshd``.

Design: §5.3.1 (see design/mssh_design_v1.md) — console-script entry.
"""
from __future__ import annotations

import sys

from .msshd import main


if __name__ == '__main__':
    sys.exit(main())
