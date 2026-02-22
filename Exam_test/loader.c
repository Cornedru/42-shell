#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int send_fd(int fd_to_send) {
    int sock;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    char abstract_name[128] = {0};
    
    abstract_name[0] = '\0';
    strncpy(abstract_name + 1, UNIX_BRIDGE, sizeof(abstract_name) - 2);
    memcpy(addr.sun_path, abstract_name, sizeof(addr.sun_path));

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Connect to receiver failed");
        close(sock);
        return -1;
    }

    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec io = { .iov_base = "SYNC", .iov_len = 4 };
    
    memset(buf, 0, sizeof(buf));
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) {
        close(sock);
        return -1;
    }
    
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = fd_to_send;

    if (sendmsg(sock, &msg, 0) < 0) {
        perror("sendmsg failed");
        close(sock);
        return -1;
    }
    
    close(sock);
    return 0;
}

static int bpf_sockmap_attach(int map_fd, int sock_fd) {
    int one = 1;
    
    if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &one, sizeof(one)) < 0) {
        perror("setsockopt SO_ATTACH_BPF");
        return -1;
    }
    
    uint32_t key = 0;
    uint64_t value = (uint64_t)sock_fd;
    
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {
        perror("bpf_map_update_elem");
        return -1;
    }
    
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int prog_fd = -1, map_fd = -1, ghost_sk = -1, netns_fd = -1;
    int ret = 1;
    uint32_t key = 0;
    
    obj = bpf_object__open_file(BPF_OBJ_PATH, NULL);
    if (!obj) {
        fprintf(stderr, "Erreur: Impossible d'ouvrir %s\n", BPF_OBJ_PATH);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Erreur: Kernel trop ancien ou privileges BPF insuffisants\n");
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "ghost_redir_port");
    if (!prog) {
        fprintf(stderr, "Erreur: Programme 'ghost_redir_port' non trouve\n");
        goto cleanup;
    }
    prog_fd = bpf_program__fd(prog);
    
    map_fd = bpf_object__find_map_fd_by_name(obj, "ghost_sock_map");
    if (map_fd < 0) {
        fprintf(stderr, "Erreur: Map 'ghost_sock_map' non trouvee\n");
        goto cleanup;
    }

    ghost_sk = socket(AF_INET, SOCK_STREAM, 0);
    if (ghost_sk < 0) {
        perror("socket");
        goto cleanup;
    }
    
    if (listen(ghost_sk, 1) < 0) {
        perror("listen");
        goto cleanup;
    }
    
    if (bpf_sockmap_attach(map_fd, ghost_sk) < 0) {
        fprintf(stderr, "Erreur: Attachement SOCKMAP echoue\n");
        goto cleanup;
    }

    netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (netns_fd < 0) {
        perror("open /proc/self/ns/net");
        goto cleanup;
    }

    if (bpf_prog_attach(prog_fd, netns_fd, BPF_SK_LOOKUP, 0) < 0) {
        perror("Attach failed (CAP_NET_ADMIN requis)");
        fprintf(stderr, "Note: Essayez: sudo setcap cap_net_admin+ep %s\n", argv[0]);
        goto cleanup;
    }

    if (send_fd(ghost_sk) < 0) {
        fprintf(stderr, "Erreur: Transfert du FD echoue\n");
        goto cleanup;
    }

    printf("[+] OK. Socket transfere au receiver. Programme BPF attache.\n");
    printf("[+] Appuyez sur ENTREE pour terminer...");
    getchar();
    
    ret = 0;

cleanup:
    if (link) bpf_link__destroy(link);
    if (netns_fd >= 0) close(netns_fd);
    if (map_fd >= 0) close(map_fd);
    if (prog_fd >= 0) close(prog_fd);
    if (obj) bpf_object__close(obj);
    if (ghost_sk >= 0) close(ghost_sk);
    
    return ret;
}
