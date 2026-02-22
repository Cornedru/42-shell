# Ghost Infrastructure — Projet Cybersécurité 42

> **Contexte académique** : Projet de spécialisation cybersécurité (post-tronc commun).  
> Ces outils implémentent des techniques offensives avancées à des fins pédagogiques : persistence, furtivité, injection mémoire, filtrage réseau via eBPF.

---

## Vue d'ensemble de l'architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     GHOST INFRASTRUCTURE                        │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Payload     │    │  Injection   │    │   Persistance    │  │
│  │  Layer       │    │  Layer       │    │   Layer          │  │
│  │              │    │              │    │                  │  │
│  │ encrypt_     │───▶│ ghost_lib.c  │───▶│ survival.sh      │  │
│  │ payload.py   │    │ (hijack.so)  │    │ master_deploy.sh│  │
│  │ stager.py    │    │              │    │ systemd service  │  │
│  └──────────────┘    └──────┬───────┘    └──────────────────┘  │
│                             │                                   │
│  ┌──────────────┐    ┌──────▼───────┐    ┌──────────────────┐  │
│  │  BPF Layer   │    │  Delivery    │    │   Nettoyage      │  │
│  │              │    │  Layer       │    │                  │  │
│  │ ghost.bpf.c  │    │ ghost_swap   │    │ full.sh          │  │
│  │ loader.c     │    │ .sh          │    │ stop_audit()     │  │
│  │ receiver.c   │    │ ghost_deploy │    │                  │  │
│  └──────────────┘    │ .sh          │    └──────────────────┘  │
│                      └──────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Fichiers du projet

| Fichier | Type | Rôle |
|---|---|---|
| `config.h` | Header C | Configuration centralisée (ports, paths, constantes) |
| `ghost_lib.c` / `hijack.so` | Bibliothèque C | Backdoor + rootkit LD_PRELOAD (cœur du projet) |
| `ghost.bpf.c` | eBPF | Redirection de trafic au niveau kernel |
| `loader.c` | C | Chargeur eBPF + transfert de FD via socket Unix |
| `receiver.c` | C | Récepteur du socket fantôme (mode ghost) |
| `evador.c` | C | Chargement .so en mémoire via `memfd_create` |
| `injector.c` | C | Injection ptrace complète dans processus distant |
| `encrypt_payload.py` | Python | Chiffrement AES-256-GCM du payload |
| `stager.py` | Python | Déchiffrement et exécution fileless en RAM |
| `ghost_deploy.sh` | Bash | Déploiement via injection LD_PRELOAD |
| `ghost_swap.sh` | Bash | Injection chirurgicale sur `gnome-terminal-server` |
| `survival.sh` | Bash | Daemon de survie (double-fork + résistance SIGTERM) |
| `master_deploy.sh` | Bash | Déploiement complet de l'infrastructure |
| `full.sh` | Bash | Script de nettoyage global |

---

## Techniques implémentées

### 1. Backdoor via LD_PRELOAD (`ghost_lib.c`, `hijack.c`)
- Injection d'une shared library dans un processus cible (`gnome-terminal-server`)
- Listener TCP sur le port 9999, spawn d'un shell interactif sur connexion
- Masquage du process via `prctl(PR_SET_NAME, "[kworker/u24:5]")`
- **Kill switch** : détection du fichier `/tmp/.ghost_off` pour auto-extinction
- Détection du processus cible via `/proc/self/exe` (plus sécurisé que comm)

### 2. Rootkit userland (hooks libc dans `hijack.so`)
- Hook de `readdir()` → masquage du file descriptor du socket dans `/proc/self/fd/`
- Hook de `recvmsg()` → filtrage des réponses Netlink pour que `ss` ne voie pas le port 9999
- Hook de `bind()` → force `SO_REUSEADDR/SO_REUSEPORT` sur tous les sockets
- Hook de `open()` → filtrage de `/proc/self/maps` et `/proc/self/environ`

### 3. Filtrage /proc avancé
- `/proc/self/maps` : masque les lignes contenant le nom de la lib (`libghost`)
- `/proc/self/environ` : filtre la variable `LD_PRELOAD=`
- Crée des fichiers temporaires dans `/tmp/.ghost_*` pour servir les données filtrées

### 4. Redirection réseau eBPF (`ghost.bpf.c` + `loader.c` + `receiver.c`)
- Programme de type `sk_lookup` attaché au namespace réseau
- Redirection forcée des paquets arrivant sur le port 9999 vers un socket fantôme
- Transfert du file descriptor entre processus via `SCM_RIGHTS` (socket Unix)
- Utilisation de `SO_ATTACH_BPF` pour SOCKMAP

### 5. Exécution fileless (`evador.c`, `stager.py`)
- Création d'un fichier en RAM via `memfd_create()` (syscall 319 sur x86_64)
- Chargement de la bibliothèque via `/proc/self/fd/<fd>` sans jamais toucher le disque
- Le payload chiffré est déchiffré en RAM puis injecté directement
- Maintien du handle via variable static (`keep_alive_handle`)

### 6. Chiffrement du payload (`encrypt_payload.py`)
- AES-256-GCM (AEAD) via `cryptography.hazmat`
- Nonce aléatoire de 12 octets préfixé au ciphertext
- Authentification intégrée (auth tag GCM)

### 7. Persistance et survie au logout (`survival.sh`, `master_deploy.sh`)
- **Double-fork** : orphelin du processus parent, adopté par PID 1
- `setsid()` : détachement du TTY de session
- `signal(SIGHUP, SIG_IGN)` et `signal(SIGTERM, SIG_IGN)`
- Persistance systemd user (`portal-service.service`) via `socat`
- `loginctl enable-linger` pour survie après déconnexion
- Lancement via `at` pour échapper au cgroup de session

### 8. Anti-cleanup et redondance (`master_deploy.sh`)
- Workspaces redondants dans `/var/tmp`, `/tmp` (4 emplacements)
- Fichier nommé `-i` dans chaque répertoire : piège pour `rm -rf *` (déclenche le mode interactif)
- Verrouillage des répertoires en `chmod 555` → `unlink()` impossible sur le contenu

### 9. Injection ptrace (`injector.c`)
- Injection complète de .so dans un processus distant via `PTRACE_ATTACH`
- Manipulation des registres (RIP, RDI, RSI) pour rediriger l'exécution vers `dlopen`
- Sauvegarde/restauration des registres originaux
- Validation des paramètres et gestion d'erreurs robuste

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
# Configuration centralisée
#  config.h pour modifier les constantes

# Bibliothèque principale (backdoor + rootkit)
gcc -fPIC -shared -o hijack.so ghost_lib.c -ldl -lpthread

# Loader fileless
gcc evador.c -o evador -ldl

# Injection ptrace
gcc injector.c -o injector -ldl

# Loader BPF (nécessite libbpf)
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src && make OBJDIR=../build DESTDIR=../install install && cd ../..
clang -O2 -target bpf -I./libbpf/install/usr/include -c ghost.bpf.c -o ghost.bpf.o
gcc loader.c -o loader -I./libbpf/install/usr/include -L./libbpf/build -l:libbpf.a -lelf -lz

# Receiver BPF
gcc receiver.c -o receiver

# Chiffrement du payload
pip install cryptography
python3 encrypt_payload.py
```

---

## Usage

```bash
# Déploiement complet
./master_deploy.sh

# Déploiement minimal (LD_PRELOAD uniquement)
./ghost_deploy.sh start
./ghost_swap.sh

# Survie au logout
./survival.sh start

# Injection ptrace (nécessite CAP_SYS_PTRACE)
gcc injector.c -o injector -ldl
./injector <pid> /chemin/vers/lib.so

# Connexion à la backdoor
nc localhost 9999    # Ghost listener (port principal)
nc localhost 8888    # Daemon de survie (port secondaire)

# Stager fileless
python3 stager.py -p payload.so.enc -k <cle_hex>

# Vérification
./ghost_deploy.sh check

# Nettoyage total
./ghost_deploy.sh stop
./survival.sh stop
./full.sh
touch /tmp/.ghost_off   # Kill switch intégré
```

---

## Corrections de sécurité appliquées

| Problème | Fichier | Correction |
|---|---|---|
| Fuite d'adresse dlopen | `injector.c` | Résolution locale, pas de fuite |
| Pas de validation des params | `injector.c` | Validation pid/chemin |
| Erreurs non gérées | `evador.c` | Vérification complète des retours |
| Clé hardcodée | `stager.py` | Passage en argument CLI |
| Integer overflow | `evador.c` | Vérification allocation |
| /proc/maps exposé | `ghost_lib.c`, `hijack.c` | Hook open() avec filtrage |
| /proc/environ exposé | `ghost_lib.c`, `hijack.c` | Filtrage LD_PRELOAD |

---

## Prérequis

- Linux x86_64 (kernel ≥ 5.9 pour eBPF sk_lookup)
- `gcc`, `clang`, `libbpf`, `libelf`, `zlib`
- Python 3 + `cryptography` (`pip install cryptography`)
- `CAP_NET_ADMIN` pour l'attachement eBPF
- `CAP_SYS_PTRACE` pour l'injection ptrace
- Environnement GNOME (pour les vecteurs `gnome-terminal-server`)

---

## Avertissement

> Ces outils sont développés dans un cadre strictement académique (École 42 — spécialisation cybersécurité).  
> Leur utilisation en dehors d'un environnement de lab isolé ou sans autorisation explicite est illégale.
