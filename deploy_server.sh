#!/bin/sh
set -e
PORT="${1:-4323}"
echo "[*] Installing LuaJIT on Alpine Linux..."
apk update && apk add --no-cache luajit

echo "[*] Stopping any existing masque-relay LuaJIT instance..."
pkill -f "luajit.*server.lua" || true

echo "[*] Starting masque-relay on UDP port $PORT..."
cd /root/wme-luajit
nohup luajit server.lua "$PORT" > /var/log/wme-relay.log 2>&1 &
sleep 1
ps aux | grep "server.lua" | grep -v grep || true
echo "[*] Live log (/var/log/wme-relay.log):"
cat /var/log/wme-relay.log
