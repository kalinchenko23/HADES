#!/usr/bin/env bash
set -euo pipefail

echo "=== ENTRYPOINT START ==="
echo "ENV: MSF_RPC_PORT=${MSF_RPC_PORT:-55552}"
echo "ENV: MSF_PASSWORD=${MSF_PASSWORD:-<unset>}"
echo "ENV: PGDATA=${PGDATA:-/var/lib/postgresql/data}"
echo

which_cmd() {
  command -v "$1" 2>/dev/null || true
}

find_binary() {
  # $1 = name
  which_cmd "$1" || find /usr /bin /opt -name "$1" 2>/dev/null | head -n1 || true
}

echo "Locating Postgres utilities..."
INITDB=$(find_binary initdb)
PG_CTL=$(find_binary pg_ctl)
PSQL=$(find_binary psql)
PG_ISREADY=$(find_binary pg_isready)
POSTGRES_BIN=$(find_binary postgres)

echo "initdb: ${INITDB:-not found}"
echo "pg_ctl: ${PG_CTL:-not found}"
echo "psql: ${PSQL:-not found}"
echo "pg_isready: ${PG_ISREADY:-not found}"
echo "postgres: ${POSTGRES_BIN:-not found}"
echo

# prepare PGDATA dir
mkdir -p "${PGDATA}"
chown -R "$(id -u ${USER:-root}):$(id -g ${USER:-root})" "${PGDATA}" || true
# If postgres tools exist, initialize DB if needed
if [ -n "${INITDB:-}" ]; then
  if [ ! -s "${PGDATA}/PG_VERSION" ]; then
    echo "Initializing PostgreSQL database in ${PGDATA}..."
    # run initdb as current user; many images expect to run as root in container
    "${INITDB}" -D "${PGDATA}" || { echo "initdb failed"; exit 1; }
    echo "Postgres initialized."
  else
    echo "Postgres DB already initialized."
  fi
else
  echo "initdb not found; postgres may not be installed correctly."
fi

# Start postgres: prefer pg_ctl, fall back to postgres -D
if [ -n "${PG_CTL:-}" ]; then
  echo "Starting postgres with pg_ctl..."
  "${PG_CTL}" -D "${PGDATA}" -l /var/log/postgres.log start || true
elif [ -n "${POSTGRES_BIN:-}" ]; then
  echo "Starting postgres directly..."
  "${POSTGRES_BIN}" -D "${PGDATA}" > /var/log/postgres.log 2>&1 &
else
  echo "No postgres control binary found. Postgres will NOT be started."
fi

# Wait for postgres to be available (use pg_isready if present)
echo "Waiting for PostgreSQL to accept connections..."
if [ -n "${PG_ISREADY:-}" ]; then
  for i in $(seq 1 30); do
    "${PG_ISREADY}" -q && break
    echo "pg_isready: waiting... ($i)"
    sleep 1
  done
else
  # fallback simple sleep
  sleep 3
fi

# Create msf user and database if psql exists
if [ -n "${PSQL:-}" ]; then
  echo "Creating msf user and database (if missing)..."
  # psql may require peer auth as postgres user; try running as postgres user if available
  if id -u postgres >/dev/null 2>&1; then
    sudo -u postgres "${PSQL}" -v ON_ERROR_STOP=1 --quiet -c "SELECT 1" >/dev/null 2>&1 || true
    sudo -u postgres "${PSQL}" -v ON_ERROR_STOP=1 --dbname=postgres <<'SQL' || true
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='msf') THEN
    CREATE ROLE msf LOGIN;
  END IF;
END$$;
CREATE DATABASE msf OWNER msf;
SQL
  else
    # Attempt as current user (may fail if auth prevents)
    "${PSQL}" -v ON_ERROR_STOP=1 --dbname=postgres <<'SQL' || true
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='msf') THEN
    CREATE ROLE msf LOGIN;
  END IF;
END$$;
CREATE DATABASE msf OWNER msf;
SQL
  fi
else
  echo "psql not available; skip DB creation."
fi

# Locate msfconsole
MSFCONSOLE=$(find_binary msfconsole)
MSFRPCD=$(find_binary msfrpcd)   # legacy binary, will use if present
MSFDB=$(find_binary msfdb)

echo "msfconsole: ${MSFCONSOLE:-not found}"
echo "msfrpcd: ${MSFRPCD:-not found}"
echo "msfdb: ${MSFDB:-not found}"
echo

# If msfdb exists, attempt to run it to configure DB (msfdb automates some setup)
if [ -n "${MSFDB:-}" ]; then
  echo "Running msfdb to setup DB (if available)..."
  # msfdb may expect interactive environment; try quick run
  "${MSFDB}" reinit || true
fi

# Start msfrpc / msgrpc
if [ -n "${MSFRPCD:-}" ]; then
  echo "Starting msfrpcd (legacy) on 0.0.0.0:${MSF_RPC_PORT}..."
  "${MSFRPCD}" -P "${MSF_PASSWORD}" -p "${MSF_RPC_PORT}" -U msf -a 0.0.0.0 &
elif [ -n "${MSFCONSOLE:-}" ]; then
  echo "Starting msgrpc by loading msgrpc inside msfconsole..."
  # start msfconsole in background and load the msgrpc plugin
  # run without ssl for simplicity; adjust SSL=true and certs if desired
  "${MSFCONSOLE}" -q -x "db_connect postgresql://msf@localhost/msf; load msgrpc ServerHost=0.0.0.0 ServerPort=${MSF_RPC_PORT} Pass=${MSF_PASSWORD} SSL=false; sleep 1; " &
else
  echo "Neither msfrpcd nor msfconsole found. Cannot start Metasploit RPC."
fi

echo "=== CONTAINER READY ==="
echo "Debug: PATH=${PATH}"
echo "Debug: which msfconsole: $(which_cmd msfconsole || echo not-found)"
echo "Debug: which psql: $(which_cmd psql || echo not-found)"

# Keep container alive and stream postgres log to stdout for convenience
tail -f /var/log/postgres.log || tail -f /dev/null
