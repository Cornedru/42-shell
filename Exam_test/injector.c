#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#define MAX_PATH_LEN 256

static int safe_ptrace(int request, pid_t pid, void *addr, void *data) {
    int ret = ptrace(request, pid, addr, data);
    if (ret < 0 && errno != 0) {
        return -1;
    }
    return ret;
}

static long get_dlopen_addr(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        return 0;
    }
    void *sym = dlsym(handle, "dlopen");
    long addr = (long)sym;
    return addr;
}

static int inject_path(int pid, unsigned long addr, const char *path) {
    size_t len = strlen(path) + 1;
    size_t words = (len + sizeof(long) - 1) / sizeof(long);
    unsigned long *data = (unsigned long *)calloc(words, sizeof(unsigned long));
    if (!data) return -1;
    
    memcpy(data, path, len);
    
    for (size_t i = 0; i < words; i++) {
        if (ptrace(PTRACE_POKEDATA, pid, addr + (i * sizeof(long)), data[i]) < 0) {
            free(data);
            return -1;
        }
    }
    
    free(data);
    return 0;
}

int inject_so(pid_t pid, const char *so_path) {
    if (pid <= 0 || !so_path) {
        fprintf(stderr, "Invalid parameters\n");
        return -1;
    }
    
    if (strlen(so_path) >= MAX_PATH_LEN) {
        fprintf(stderr, "Path too long\n");
        return -1;
    }
    
    long dlopen_addr = get_dlopen_addr();
    if (dlopen_addr == 0) {
        fprintf(stderr, "Failed to resolve dlopen address\n");
        return -1;
    }
    
    if (safe_ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace attach");
        return -1;
    }
    
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Target process did not stop\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    struct user_regs_struct regs, old_regs;
    if (safe_ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace getregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    memcpy(&old_regs, &regs, sizeof(regs));
    
    unsigned long inj_addr = (unsigned long)regs.rsp - 128;
    if (inject_path(pid, inj_addr, so_path) < 0) {
        fprintf(stderr, "Failed to inject path\n");
        ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    regs.rip = (unsigned long)dlopen_addr;
    regs.rdi = inj_addr;
    regs.rsi = RTLD_LAZY;
    
    if (safe_ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace setregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    if (safe_ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("ptrace cont");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    usleep(100000);
    
    safe_ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
    safe_ptrace(PTRACE_DETACH, pid, NULL, NULL);
    
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <path_to_so>\n", argv[0]);
        return 1;
    }
    
    pid_t pid = atoi(argv[1]);
    const char *so_path = argv[2];
    
    return inject_so(pid, so_path);
}
