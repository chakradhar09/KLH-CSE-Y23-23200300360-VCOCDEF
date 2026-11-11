#!/usr/bin/env python3
"""Shim: the code lives in src/vcoc/verifier.py. Keeps `python verifier.py ...` and `import verifier` working; installed, use `vcoc verify`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from vcoc import verifier as _real  # noqa: E402

if __name__ == "__main__":
    _real.main()
else:
    sys.modules[__name__] = _real
