"""Pytest bootstrap.

Ensures ``src`` is importable even when an editable install's ``.pth`` is unavailable (e.g. uv's
editable install mishandles directory paths that contain a space). Normal installs are unaffected;
this only *prepends* the source tree when present.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
