import argparse
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.exceptions import InvalidTag
import os

def damage_test(ciphertext, iv, tag, key, ad, elements):
    for element in elements:
        if element == "c":
            #alter ciphertext
            ciphertext = ciphertext[:-16] + os.urandom(16)
            print(f"Altered ciphertext: {ciphertext.hex()}")
        if element == "iv":
            #alter iv
            iv = os.urandom(16)
            print(f"Altered iv: {iv.hex()}")
        if element == "key":
            #alter key
            key = os.urandom(16)
            print(f"Altered key: {key.hex()}")
        if element == "tag":    
            #alter tag
            tag = os.urandom(16)
            print(f"Altered tag: {tag.hex()}")
        if element == "ad":
            #alter associated data
            ad = os.urandom(16)
            print(f"Altered associated data: {ad.hex()}")
    #try to decrypt
    plaintext = decrypt(ciphertext, key, iv, tag, ad)

def encrypt(plaintext, key, ad):
    iv = os.urandom(16) # Generate a 128-bit IV randomly
    # Create an AES-128-GCM cipher object
    cipher = Cipher(algorithms.AES(key),modes.GCM(iv))
    encryptor = cipher.encryptor()
    # Authenticate associated data
    encryptor.authenticate_additional_data(ad)
    # Encrypt the plaintext and get the associated ciphertext and tag
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (ciphertext, iv, encryptor.tag)

def decrypt(ciphertext, key, iv, tag, ad):
    cipher = Cipher(algorithms.AES(key),modes.GCM(iv,tag))
    decryptor = cipher.decryptor()
    # Authenticate associated data
    decryptor.authenticate_additional_data(ad)
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except InvalidTag as e:
        print(f"Error: Invalid Tag")
        return None

def main():
    parser = argparse.ArgumentParser(description="Encrypt, decrypt, or corrupt data using a specified encryption algorithm.")
    parser.add_argument("-e", action="store_true", help="Encrypt mode")
    parser.add_argument("-d", action="store_true", help="Decrypt mode")
    parser.add_argument("-c", action="store_true", help="Corrupt mode")
    parser.add_argument("-t", required=True, help="Text encoded in hexadecimal format")
    parser.add_argument("-a", help="Associated Data")
    parser.add_argument("-k", required=True, help="Key encoded in hexadecimal format")
    parser.add_argument("-iv", help="Initialization Vector (IV)")
    parser.add_argument("-g", help="Tag accompanying the data")
    parser.add_argument("-m", nargs='+', choices=['c', 'iv', 'key', 'tag', 'ad'], help="Elements to damage in corruption mode")

    args = parser.parse_args()

    # Convert to bytes
    text = bytes.fromhex(args.t)
    key = bytes.fromhex(args.k)
    if args.iv:
        iv = bytes.fromhex(args.iv)
    if args.g:
        tag = bytes.fromhex(args.g)
    if args.a:
        ad = bytes.fromhex(args.a)

    #select mode and run accordingly
    if args.e and args.a:
        ciphertext, iv, tag = encrypt(text, key, ad)
        print(f"Ciphertext: {ciphertext.hex()}")
        print(f"IV: {iv.hex()}")
        print(f"Tag: {tag.hex()}")
    elif args.d:
        plaintext = decrypt(text, key, iv, tag, ad)
        print(f"Plaintext: {plaintext.hex()}")
    elif args.c:
        damage_test(text, iv, tag, key, ad, args.m)

    #example run for encryption: python3 GCM_AEAD_integrity.py -e -t 54686973206973206120736563726574206d6573736167652e -k 000102030405060708090a0b0c0d0e0f -a 54686973206973206120736563726574206173736f6369617465642064617461
if __name__ == "__main__":
    main()
