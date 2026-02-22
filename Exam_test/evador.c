#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#define SO_PATH "hijack.so"

static void *keep_alive_handle = NULL;

static void *load_fileless(unsigned char *buffer, size_t size) {
    int fd = -1;
    void *handle = NULL;
    char fd_path[64];
    int ret;

    fd = memfd_create("ghost_lib", MFD_CLOEXEC);
    if (fd == -1) {
        perror("memfd_create");
        return NULL;
    }
    
    ret = write(fd, buffer, size);
    if (ret != (ssize_t)size) {
        perror("write");
        close(fd);
        return NULL;
    }
    
    off_t seek_ret = lseek(fd, 0, SEEK_SET);
    if (seek_ret < 0) {
        perror("lseek");
        close(fd);
        return NULL;
    }

    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    
    handle = dlopen(fd_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        close(fd);
        return NULL;
    }
    
    keep_alive_handle = handle;
    
    return handle;
}

int main(int argc, char **argv) {
    int file_fd = -1;
    size_t size = 0;
    unsigned char *buffer = NULL;
    void *handle = NULL;
    ssize_t bytes_read;
    int ret = 1;

    file_fd = open(SO_PATH, O_RDONLY);
    if (file_fd == -1) {
        fprintf(stderr, "Erreur: Impossible d'ouvrir %s: %s\n", SO_PATH, strerror(errno));
        return 1;
    }
    
    off_t seek_ret = lseek(file_fd, 0, SEEK_END);
    if (seek_ret < 0) {
        perror("lseek");
        goto cleanup;
    }
    size = (size_t)seek_ret;
    
    seek_ret = lseek(file_fd, 0, SEEK_SET);
    if (seek_ret < 0) {
        perror("lseek");
        goto cleanup;
    }
    
    buffer = malloc(size);
    if (!buffer) {
        fprintf(stderr, "Erreur: Allocation memoire echouee\n");
        goto cleanup;
    }
    
    bytes_read = read(file_fd, buffer, size);
    if (bytes_read != (ssize_t)size) {
        fprintf(stderr, "Erreur: Lecture incomplete (%zd/%zu)\n", bytes_read, size);
        goto cleanup;
    }

    handle = load_fileless(buffer, size);
    if (handle) {
        printf("[+] Bibliotheque chargee en memoire.\n");
        printf("[+] Handle: %p\n", handle);
        printf("[+] Le fichier source peut maintenant etre supprime.\n");
        printf("[+] Appuyez sur ENTREE pour quitter (la lib reste chargee)...\n");
        getchar();
        ret = 0;
    } else {
        fprintf(stderr, "Erreur: Chargement fileless echoue\n");
    }

cleanup:
    if (buffer) free(buffer);
    if (file_fd >= 0) close(file_fd);
    
    return ret;
}
