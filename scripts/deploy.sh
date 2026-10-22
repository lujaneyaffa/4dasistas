#!/bin/sh
# The ONE way to deploy: checks -> deploy from the repo root (so the site's static files stay attached) -> live check.
cd "$(dirname "$0")/.." || exit 1
sh scripts/predeploy.sh || exit 1
npx wrangler deploy 2>&1 | tail -3
sleep 10
sh scripts/postdeploy-check.sh
