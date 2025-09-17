#!/usr/bin/env bash
set -euo pipefail

MSF_PASSWORD="${MSF_PASSWORD:-password}"
MSF_PORT="${MSF_RPC_PORT:-55552}"

# Start PostgreSQL
# Use service scripts common in Debian-based images. In some environments you may need to
# use `pg_ctl` or similar — adjust if your image differs.
if command -v service >/dev/null 2>&1; then
  service postgresql start || /etc/init.d/postgresql start || true
else
  echo "service command not found. Ensure postgres is started by other means."
fi

# Wait a short moment for postgres to be ready
sleep 2

# Initialize Metasploit DB if helper exists (optional)
if command -v msfdb >/dev/null 2>&1; then
  # msfdb init is safe if already initialized; ignore errors if present
  msfdb init || true
fi

# Start msfrpcd in foreground so Docker container stays alive
# Flags: -P <password> -a <bind addr> -p <port> -f (foreground)
# Depending on Metasploit package version the flags might differ. Adjust if needed.
if command -v msfrpcd >/dev/null 2>&1; then
  echo "Starting msfrpcd on 0.0.0.0:${MSF_PORT}"
  # start in foreground so Docker supervises it
  exec msfrpcd -P "${MSF_PASSWORD}" -a 0.0.0.0 -p "${MSF_PORT}" -f
else
  echo "msfrpcd not installed. Install metasploit-framework with msfrpcd present."
  tail -f /dev/null
fi
