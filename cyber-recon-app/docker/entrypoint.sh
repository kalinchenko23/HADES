#!/bin/bash

echo "=== Starting Metasploit Container ==="

# Verify installations first
echo "Checking installations..."
if ! command -v msfconsole >/dev/null; then
    echo "ERROR: msfconsole not found!"
    exit 1
fi

if ! command -v psql >/dev/null; then
    echo "ERROR: PostgreSQL not found!"
    exit 1
fi

# Start PostgreSQL
echo "Starting PostgreSQL..."
service postgresql start || systemctl start postgresql || {
    echo "Service start failed, trying manual start..."
    su postgres -c "/usr/lib/postgresql/*/bin/postgres -D /var/lib/postgresql/*/main" &
}

# Wait for PostgreSQL
sleep 10

# Check if PostgreSQL is running
if pgrep -x postgres >/dev/null; then
    echo "PostgreSQL is running"
else
    echo "WARNING: PostgreSQL may not be running properly"
fi

# Initialize Metasploit database
echo "Initializing Metasploit database..."
msfdb init || echo "msfdb init failed, continuing..."

# Alternative database setup using msfconsole
echo "Setting up database via msfconsole..."
timeout 30 msfconsole -q -x "db_status; exit" || echo "Database setup failed"

# Start Metasploit RPC daemon
echo "Starting Metasploit RPC on port $MSF_RPC_PORT..."

# Try multiple methods to start RPC
if command -v msfrpcd >/dev/null; then
    echo "Using msfrpcd binary"
    msfrpcd -P "$MSF_PASSWORD" -S -a 0.0.0.0 -p "$MSF_RPC_PORT" -f &
else
    echo "Using msfconsole to start RPC"
    nohup msfconsole -q -x "load msgrpc ServerHost=0.0.0.0 ServerPort=$MSF_RPC_PORT Pass=$MSF_PASSWORD SSL=false" > /tmp/msf-rpc.log 2>&1 &
fi

# Wait for RPC to start
sleep 10

# Check if RPC is running
if netstat -tlnp | grep ":$MSF_RPC_PORT" >/dev/null; then
    echo "SUCCESS: Metasploit RPC is running on port $MSF_RPC_PORT"
else
    echo "WARNING: No service detected on port $MSF_RPC_PORT"
    echo "Check logs in /tmp/msf-rpc.log"
fi

echo "Container ready!"
echo "RPC Port: $MSF_RPC_PORT"
echo "RPC Password: $MSF_PASSWORD"

# Keep container running
tail -f /tmp/msf-rpc.log 2>/dev/null &
tail -f /dev/null