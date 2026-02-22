#ifndef GHOST_CONFIG_H
# define GHOST_CONFIG_H

# define GHOST_PORT          9999
# define SURVIVAL_PORT       8888
# define KILL_SWITCH         "/tmp/.ghost_off"
# define FAKE_THREAD_NAME    "[kworker/u24:5]"
# define UNIX_BRIDGE        "ghost_bridge"
# define BPF_OBJ_PATH        "ghost.bpf.o"
# define GHOST_SO_NAME       "libghost"

# define TARGET_COMM_1       "gnome-terminal"
# define TARGET_COMM_2       "zsh"

# ifndef GHOST_FULL_ROOTKIT
#  define GHOST_FULL_ROOTKIT 0
# endif

#endif
