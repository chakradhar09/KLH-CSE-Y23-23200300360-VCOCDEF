#!/bin/sh
# Installs the `vcoc` command for the current user (Linux, macOS, Git Bash). Needs nothing installed first: it gets uv
# if missing, uv downloads Python 3.12 if missing, and vcoc's packages go into vcoc's own environment.
#   From a clone:      ./install.sh
#   Without a clone:   curl -fsSL https://raw.githubusercontent.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF/main/install.sh | sh
# Run it again to update. Remove vcoc with `vcoc uninstall`.
set -e
ARCHIVE="https://github.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF/archive/refs/heads/main.zip"
PYTHON=3.12

if ! command -v uv >/dev/null 2>&1; then
    echo "Installing uv (Python and package manager, https://docs.astral.sh/uv/) ..."
    if command -v curl >/dev/null 2>&1; then curl -LsSf https://astral.sh/uv/install.sh | sh
    else wget -qO- https://astral.sh/uv/install.sh | sh; fi
    PATH="$HOME/.local/bin:$PATH"
    command -v uv >/dev/null 2>&1 || { echo "ERROR: uv did not install. Check your internet connection and run this again." >&2; exit 1; }
fi

DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)
if [ -n "$DIR" ] && [ -f "$DIR/pyproject.toml" ]; then SOURCE="$DIR"; else SOURCE="$ARCHIVE"; fi
echo "Installing vcoc from $SOURCE with Python $PYTHON ..."
uv tool install --force --python "$PYTHON" "$SOURCE"
uv tool update-shell >/dev/null 2>&1 || true

echo
echo "Done. Open a new terminal and run:  vcoc help"
