#!/usr/bin/env bash
# ws - wrapper: accept either "Ws http://..." or "ws http://..."
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# If first arg looks like a URL (starts with http or www or contains a dot), insert "Ws" before it
if [[ $# -ge 1 ]]; then
  first="$1"
  if [[ "$first" =~ ^https?:// ]] || [[ "$first" =~ ^www\. ]] || [[ "$first" =~ \. ]]; then
    set -- "Ws" "$@"
  fi
fi

python3 "$DIR/enhanced_webscan.py" "$@"
