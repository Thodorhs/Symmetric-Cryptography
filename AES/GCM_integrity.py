from AES_128_GCM import encrypt, decrypt
import os
import argparse

def test(key, ciphertext, iv, tag, elements):
    print("===================== Testing integrity =======================")
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
    decrypted = decrypt(ciphertext, key, iv, tag)
    if decrypted == None:
        print("================================= Test gave no decryption ============================================")
    else:
        print(f"Decrypted  : {decrypted.decode('latin')}")
        print("================================= Test Passed ============================================")
def main():
    parser = argparse.ArgumentParser(description="Encrypt and damage encryption elements.")
    parser.add_argument("-p", "--plaintext", required=True, help="The plaintext")
    parser.add_argument("-k", "--key", required=True, help="The key encoded in hexadecimal format")
    parser.add_argument("-e", "--elements", nargs="+", choices=["c", "iv", "key", "tag"], required=True, help="Encryption elements to damage (c, iv, key, tag)")

    args = parser.parse_args()
    
    plaintext = bytes.fromhex(args.plaintext)
    key = bytes.fromhex(args.key)

    ciphertext, iv, tag = encrypt(plaintext, key)

    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Tag: {tag.hex()}")
    # an example of run: python3 GCM_integrity.py -p 54686973206973206120736563726574206d6573736167652e -k 000102030405060708090a0b0c0d0e0f -e c iv key tag
    test(key, ciphertext, iv, tag, args.elements)

if __name__ == "__main__":
    main()