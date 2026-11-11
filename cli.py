#!/usr/bin/env python3
"""Shim: the code lives in src/vcoc/cli.py. Keeps `python cli.py ...` and `import cli` working; installed, use `vcoc`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from vcoc import cli as _real  # noqa: E402

if __name__ == "__main__":
    _real.main()
else:
    sys.modules[__name__] = _real
