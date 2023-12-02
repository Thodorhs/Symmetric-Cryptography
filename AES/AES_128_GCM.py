from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.exceptions import InvalidTag
import argparse
import os

def encrypt(plaintext, key):
    iv = os.urandom(12)
    # Create an AES-128-GCM cipher object
    cipher = Cipher(algorithms.AES(key),modes.GCM(iv))
    encryptor = cipher.encryptor()

    # Encrypt the plaintext and get the associated ciphertext and tag
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return (ciphertext, iv, encryptor.tag)

def decrypt(ciphertext, key, iv, tag):
    cipher = Cipher(algorithms.AES(key),modes.GCM(iv,tag))
    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except InvalidTag as e:
        print(f"Error: Invalid Tag")
        return None

def test(key):
    print("==================== Running Test feeding encrypted text back into decryptor ====================")
    plaintext = b"this is a secret message."
    ciphertext, iv, tag = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key, iv, tag)
    print(f"Key        : {key.hex()}")
    print(f"IV         : {iv.hex()}")
    print(f"Tag        : {tag.hex()}")
    print(f"Plaintext  : {plaintext}")
    print(f"Ciphertext : {ciphertext.hex()}")
    if decrypted == plaintext:
        print(f"Decrypted  : {decrypted.decode('utf-8')}")
        print("================================= Test Passed ============================================")
    else:
        print("================================= Test Failed ============================================")

    print("==================== Running Test feeding encrypted text back into decryptor (wrong tag) ====================")
    plaintext = b"this is a secret message."
    ciphertext, iv, tag = encrypt(plaintext, key)
    tag = b'ffffffffffffffff'
    decrypted = decrypt(ciphertext, key, iv, tag)
    print(f"Key        : {key.hex()}")
    print(f"IV         : {iv.hex()}")
    print(f"Tag        : {tag.hex()}")
    print(f"Plaintext  : {plaintext}")
    print(f"Ciphertext : {ciphertext.hex()}")
    if decrypted == None:
        print("================================= Test Passed ============================================")
    else:
        print("================================= Test Failed ============================================")

def main():
    parser = argparse.ArgumentParser(description="AES-GCM Encryption and Decryption")
    parser.add_argument("-e", action="store_true", help="Encrypt mode")
    parser.add_argument("-d", action="store_true", help="Decrypt mode")
    parser.add_argument("-t", required=True, help="Text in hexadecimal format")
    parser.add_argument("-k", required=True, help="Key in hexadecimal format")
    parser.add_argument("-iv", required=False, help="Initialization Vector in hexadecimal format")
    parser.add_argument("-g", required=False, help="Tag in hexadecimal format")

    args = parser.parse_args()

    text = bytes.fromhex(args.t)
    key = bytes.fromhex(args.k)
    
    if args.e:
        #example of a run command: python3 AES_128_GCM.py -e -t 54686973206973206120736563726574206d6573736167652e -k 000102030405060708090a0b0c0d0e0f
        ciphertext, iv, tag = encrypt(text, key)
        print(f"Ciphertext: {ciphertext.hex()}")
        print(f"Key: {key.hex()}")
        print(f"IV: {iv.hex()}")
        print(f"Tag: {tag.hex()}")

    elif args.d:
        iv = bytes.fromhex(args.iv)
        tag = bytes.fromhex(args.g)
        plaintext = decrypt(text, key, iv, tag)
        print(f"Plaintext: {plaintext.hex()}")

    else:
        test(key)
        print("Please specify either -e (encrypt) or -d (decrypt)")

if __name__ == "__main__":
    main()