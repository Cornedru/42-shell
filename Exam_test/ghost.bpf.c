#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

// Map pour stocker le socket de destination
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ghost_sock_map SEC(".maps");

SEC("sk_lookup")
int ghost_redir_port(struct bpf_sk_lookup *ctx) {
    __u32 key = 0;

    // Filtre sur le port cible
    if (ctx->local_port != 9999)
        return SK_PASS;

    // Recherche du socket injecté par le loader
    struct bpf_sock *sk = bpf_map_lookup_elem(&ghost_sock_map, &key);
    if (!sk)
        return SK_PASS;

    // Assignation du paquet au socket (redirection forcée)
    // Le flag 0 indique que nous ne vérifions pas l'état d'écoute standard
    long err = bpf_sk_assign(ctx, sk, 0);
    
    // Libération de la référence incrémentée par bpf_map_lookup_elem
    bpf_sk_release(sk);

    return (err == 0) ? SK_PASS : SK_DROP;
}

char _license[] SEC("license") = "GPL";