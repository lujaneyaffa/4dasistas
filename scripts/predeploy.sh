#!/bin/sh
# Run before EVERY deploy: syntax-checks every inline <script> in the pages and the Worker. A script error is what causes a white screen.
cd "$(dirname "$0")/.." || exit 1
tmp=$(mktemp -d); fail=0
for f in index.html badminton.html offline.html; do
  [ -f "$f" ] || continue
  python3 - "$f" "$tmp" <<'PY'
import re,sys
s=open(sys.argv[1]).read()
for i,x in enumerate(re.findall(r'<script(?![^>]*\bsrc=)(?![^>]*type="(?:application/ld\+json|text/template)")[^>]*>(.*?)</script>',s,re.S)):
    open(f"{sys.argv[2]}/{sys.argv[1]}.{i}.js","w").write(x)
PY
done
for j in "$tmp"/*.js; do [ -f "$j" ] && { node --check "$j" 2>&1 | head -5; [ "${PIPESTATUS:-0}" ] ; node --check "$j" >/dev/null 2>&1 || { echo "SYNTAX ERROR in $(basename "$j")"; fail=1; }; }; done
node --check workers/src/worker.js >/dev/null 2>&1 || { echo "SYNTAX ERROR in worker.js"; fail=1; }
node --check service-worker.js >/dev/null 2>&1 || { echo "SYNTAX ERROR in service-worker.js"; fail=1; }
rm -rf "$tmp"
[ $fail = 0 ] && echo "predeploy OK" || { echo "DO NOT DEPLOY"; exit 1; }
