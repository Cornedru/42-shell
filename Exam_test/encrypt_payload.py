# encrypt_payload.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_so(input_path, output_path, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Chiffrement (data + nonce + auth tag)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    with open(output_path, 'wb') as f:
        f.write(nonce + ciphertext)
    print(f"[+] Payload chiffré : {output_path}")

# Génération d'une clé de 32 octets (AES-256)
key = os.urandom(32)
encrypt_so("hijack.so", "payload.so.enc", key)
print(f"[*] Clé (hex) : {key.hex()}")