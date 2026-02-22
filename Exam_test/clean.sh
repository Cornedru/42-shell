#!/bin/bash
# full.sh
pkill -9 -f "nc -l -p 8888"
# pkill -p -f "4444"
# pkill -p -f "4445"
# pkill -p -f "4343"
# pkill -p -f "7777"
pkill -9 -f "kworker/u24:5"
unset LD_PRELOAD
rm -f /tmp/.ghost_off
echo "[+] Workspace clean."