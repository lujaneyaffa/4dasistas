#!/bin/sh
# The ONE way to deploy: checks -> deploy from the repo root (so the site's static files stay attached) -> live check.
cd "$(dirname "$0")/.." || exit 1
# GUARD: events/resources accepted via email or the editor are committed to GitHub by the Worker. Deploying a stale local copy wipes them from the site.
git fetch -q origin 2>/dev/null && [ "$(git rev-list --count HEAD..origin/main 2>/dev/null)" != "0" ] && { echo "STOP: origin/main has commits you don't have (accepted events/resources). Run: git merge origin/main   then deploy again."; exit 1; }
sh scripts/predeploy.sh || exit 1
npx wrangler deploy 2>&1 | tail -3
sleep 10
sh scripts/postdeploy-check.sh
