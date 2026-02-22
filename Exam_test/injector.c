#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Note : Ce code est simplifié pour illustrer la manipulation des registres x86_64
void inject_so(int pid, char *so_path) {
    struct user_regs_struct regs, old_regs;
    long addr;

    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    memcpy(&old_regs, &regs, sizeof(regs));

    // 1. Trouver l'adresse de dlopen dans le processus cible
    // (Généralement via l'offset dans libc.so + adresse de base de libc dans /proc/PID/maps)
    void *dlopen_addr = dlsym(dlopen(NULL, RTLD_LAZY), "dlopen"); 

    // 2. Injecter le chemin de la lib en mémoire (ex: sur la pile ou zone RW)
    // 3. Modifier RIP pour pointer sur dlopen
    // 4. Mettre RDI (1er arg) vers l'adresse du chemin, RSI (2e arg) à RTLD_LAZY (1)
    
    // Pour une injection réelle, on injecterait un petit shellcode "loader"
    // qui fait l'appel et provoque un SIGTRAP pour nous rendre la main.
    
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    // ... wait for trap, then restore old_regs and detach ...
}