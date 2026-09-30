#!/bin/sh
# Render (and some other hosts) mount persistent disks owned by root. Fix the
# ownership of the data dir, then drop privileges before starting the app.
set -e
DATA_DIR="$(dirname "${SPIDERLY_DB_PATH:-/data/spiderly.db}")"
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR"
  chown spiderly:spiderly "$DATA_DIR" 2>/dev/null || true
  exec setpriv --reuid=spiderly --regid=spiderly --clear-groups "$@"
fi
exec "$@"
