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
│  │ payload.py   │    │ (hijack.so)  │    │ master_deploy.sh │  │
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
| `ghost_lib.c` / `hijack.so` | Bibliothèque C | Backdoor + rootkit LD_PRELOAD (cœur du projet) |
| `ghost.bpf.c` | eBPF | Redirection de trafic au niveau kernel |
| `loader.c` | C | Chargeur eBPF + transfert de FD via socket Unix |
| `receiver.c` | C | Récepteur du socket fantôme (mode ghost) |
| `fileless_loader.c` | C | Chargement .so en mémoire via `memfd_create` |
| `encrypt_payload.py` | Python | Chiffrement AES-256-GCM du payload |
| `stager.py` | Python | Déchiffrement et exécution fileless en RAM |
| `ghost_deploy.sh` | Bash | Déploiement via injection LD_PRELOAD |
| `ghost_swap.sh` | Bash | Injection chirurgicale sur `gnome-terminal-server` |
| `survival.sh` | Bash | Daemon de survie (double-fork + résistance SIGTERM) |
| `master_deploy.sh` | Bash | Déploiement complet de l'infrastructure |
| `full.sh` | Bash | Script de nettoyage global |

---

## Techniques implémentées

### 1. Backdoor via LD_PRELOAD (`ghost_lib.c`)
- Injection d'une shared library dans un processus cible (`gnome-terminal-server`)
- Listener TCP sur le port 9999, spawn d'un shell interactif sur connexion
- Masquage du process via `prctl(PR_SET_NAME, "[kworker/u24:5]")`
- **Kill switch** : détection du fichier `/tmp/.ghost_off` pour auto-extinction

### 2. Rootkit userland (hooks libc dans `hijack.so`)
- Hook de `readdir()` → masquage du file descriptor du socket dans `/proc/self/fd/`
- Hook de `recvmsg()` → filtrage des réponses Netlink pour que `ss` ne voie pas le port 9999
- Hook de `bind()` → force `SO_REUSEADDR/SO_REUSEPORT` sur tous les sockets

### 3. Redirection réseau eBPF (`ghost.bpf.c` + `loader.c` + `receiver.c`)
- Programme de type `sk_lookup` attaché au namespace réseau
- Redirection forcée des paquets arrivant sur le port 9999 vers un socket fantôme
- Transfert du file descriptor entre processus via `SCM_RIGHTS` (socket Unix)

### 4. Exécution fileless (`fileless_loader.c`, `stager.py`)
- Création d'un fichier en RAM via `memfd_create()` (syscall 319 sur x86_64)
- Chargement de la bibliothèque via `/proc/self/fd/<fd>` sans jamais toucher le disque
- Le payload chiffré est déchiffré en RAM puis injecté directement

### 5. Chiffrement du payload (`encrypt_payload.py`)
- AES-256-GCM (AEAD) via `cryptography.hazmat`
- Nonce aléatoire de 12 octets préfixé au ciphertext
- Authentification intégrée (auth tag GCM)

### 6. Persistance et survie au logout (`survival.sh`, `master_deploy.sh`)
- **Double-fork** : orphelin du processus parent, adopté par PID 1
- `setsid()` : détachement du TTY de session
- `signal(SIGHUP, SIG_IGN)` et `signal(SIGTERM, SIG_IGN)`
- Persistance systemd user (`portal-service.service`) via `socat`
- `loginctl enable-linger` pour survie après déconnexion
- Lancement via `at` pour échapper au cgroup de session

### 7. Anti-cleanup et redondance (`master_deploy.sh`)
- Workspaces redondants dans `/var/tmp`, `/tmp` (4 emplacements)
- Fichier nommé `-i` dans chaque répertoire : piège pour `rm -rf *` (déclenche le mode interactif)
- Verrouillage des répertoires en `chmod 555` → `unlink()` impossible sur le contenu

### 8. Injection ptrace (`ptrace_inject.c`)
- Démonstration d'injection de .so dans un processus distant via `PTRACE_ATTACH`
- Manipulation des registres (RIP, RDI, RSI) pour rediriger l'exécution vers `dlopen`

---

## Compilation

```bash
# Bibliothèque principale (backdoor + rootkit)
gcc -fPIC -shared -o hijack.so ghost_lib.c -ldl -lpthread

# Loader fileless
gcc fileless_loader.c -o fileless_loader -ldl

# Survival daemon
gcc survival_daemon.c -o .sys_core

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

# Connexion à la backdoor
nc localhost 9999    # Ghost listener (port principal)
nc localhost 8888    # Daemon de survie (port secondaire)

# Vérification
./ghost_deploy.sh check

# Nettoyage total
./ghost_deploy.sh stop
./survival.sh stop
./full.sh
touch /tmp/.ghost_off   # Kill switch intégré
```

---

## Prérequis

- Linux x86_64 (kernel ≥ 5.9 pour eBPF sk_lookup)
- `gcc`, `clang`, `libbpf`, `libelf`, `zlib`
- Python 3 + `cryptography` (`pip install cryptography`)
- `CAP_NET_ADMIN` pour l'attachement eBPF
- Environnement GNOME (pour les vecteurs `gnome-terminal-server`)

---

## Avertissement

> Ces outils sont développés dans un cadre strictement académique (École 42 — spécialisation cybersécurité).  
> Leur utilisation en dehors d'un environnement de lab isolé ou sans autorisation explicite est illégale.