#!/usr/bin/env python3
"""Shim: the code lives in src/vcoc/witness.py. Keeps `python witness.py ...` and `import witness` working; installed, use `vcoc witness`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from vcoc import witness as _real  # noqa: E402

if __name__ == "__main__":
    _real.main()
else:
    sys.modules[__name__] = _real
