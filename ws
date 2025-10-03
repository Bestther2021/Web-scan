#!/usr/bin/env bash
# ws - wrapper to run enhanced_webscan.py in same folder
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$DIR/enhanced_webscan.py" "$@"
