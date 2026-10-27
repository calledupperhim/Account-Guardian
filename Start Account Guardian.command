#!/bin/bash
cd "$(dirname "$0")"
if command -v python3 >/dev/null; then python3 guardian.py
else echo "Python 3 not found. Install from https://www.python.org/downloads/"; open https://www.python.org/downloads/; read -p "Press Enter"; fi
