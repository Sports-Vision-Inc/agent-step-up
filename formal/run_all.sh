#!/usr/bin/env bash
# Run every Tamarin model/lemma (revision 2, D-005) with a per-lemma timeout
# and write formal/results.json; exits non-zero on any mismatch against the
# expected table or any error (including a failed wellformedness check).
#   TIMEOUT=600 formal/run_all.sh            # default 600 s per lemma
#   formal/run_all.sh --only maude --out /tmp/maude.json   # legacy bounded Maude encoding
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HERE/bin:$PATH"
export LC_ALL=C.UTF-8
exec python3 "$HERE/run_all.py" --timeout "${TIMEOUT:-600}" "$@"
