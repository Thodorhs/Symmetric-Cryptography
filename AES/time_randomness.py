import random
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(plaintext, key, iv):
    # Create an AES-128-GCM cipher object
    cipher = Cipher(algorithms.AES(key),modes.GCM(iv))
    encryptor = cipher.encryptor()

    # Encrypt the plaintext and get the associated ciphertext and tag
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return (ciphertext, iv, encryptor.tag)

def key_iv_gen():
    seconds = int(time.time())
    millisecs = int(time.time()*1000) % 1000
    pid = os.getpid() % 10000
    seed = seconds*0x68793435382d63727970746f + pid*0x677261706879 + millisecs
    r = random.Random(seed)
    key = r.randbytes(16)
    iv = r.randbytes(12)
    return key, iv

if __name__ == "__main__":
    print ("Time is : ", time.time())
    key, iv = key_iv_gen()
    plaintext = b"this is a secret message."
    ciphertext, iv, tag = encrypt(plaintext, key, iv)
    print(f"Key        : {key.hex()}")
    print(f"IV         : {iv.hex()}")
    print(f"Tag        : {tag.hex()}")
    print(f"Plaintext  : {plaintext.hex()}")
    print(f"Ciphertext : {ciphertext.hex()}")

