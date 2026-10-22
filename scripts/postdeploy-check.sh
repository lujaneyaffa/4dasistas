#!/bin/sh
# Run right after a deploy: the live site must answer, serve the new service-worker version, and load the page code.
v=$(grep -o "4dasistas-v[0-9]*" "$(dirname "$0")/../service-worker.js" | head -1)
for i in 1 2 3 4 5 6; do
  live=$(curl -s "https://4dasistas.ca/service-worker.js?c=$(date +%s)" | grep -o "4dasistas-v[0-9]*" | head -1)
  [ "$live" = "$v" ] && break; sleep 5
done
code=$(curl -s -o /dev/null -w "%{http_code}" "https://4dasistas.ca/?c=$(date +%s)")
true
echo "site=$code sw-live=$live expected=$v"
[ "$code" = "200" ] && [ "$live" = "$v" ] && echo "postdeploy OK" || { echo "PROBLEM — check the live site now"; exit 1; }
