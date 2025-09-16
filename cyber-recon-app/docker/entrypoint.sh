#!/bin/bash
set -e

# Ensure postgres data dir permissions exist (adjust for your Postgres version)
mkdir -p /var/lib/postgresql
chown -R postgres:postgres /var/lib/postgresql || true

# Start supervisor (which runs postgres and msfrpcd)
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
