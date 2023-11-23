import argparse
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from AES_128_CBC import AES_128_CBC_encrypt, byte_xor

def AES_random_access(ciphertext, key, iv, index):
    #assert index >= 0
    if index < 0:
        raise argparse.ArgumentTypeError(f"Invalid index: {index}")
    # Create an AES-128-ECB cipher object
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    depcryptor = cipher.decryptor()
    i = index * 16
    print("Random Access for Block:", ciphertext[i:i+16].hex(), "at index:", index)
    pt = depcryptor.update(ciphertext[i:i+16])
    if i == 0:
        print("Using IV for XOR:", iv.hex())
        xor_block = byte_xor(iv, pt[0:16])
    else:
        print("Using previous block for XOR:", ciphertext[i-16:i].hex(), "at index:", index-1)
        xor_block = byte_xor(pt, ciphertext[i-16:i])
    print("Plain Text:", xor_block.hex())
    
    return

def test(cipher, key, iv, index):
    print("=====================RANDOM ACCESS==========================")
    AES_random_access(cipher, key, iv, index)
    print("============================================================")
    return

def main():
    parser = argparse.ArgumentParser(description="AES_128_CBC Encrypt/Decrypt arguments.")
    parser.add_argument("-p",  required=True, help="The plaintext, encoded in hexadecimal format")
    parser.add_argument("-k",  required=True, help="The key, encoded in hexadecimal format")
    parser.add_argument("-iv", required=True, help="The IV, encoded in hexadecimal format")

    args = parser.parse_args()
    
    plaintext = args.p
    key = args.k
    iv = args.iv

    #check if key and iv are 16 bytes
    if len(key) != 32:
        raise argparse.ArgumentTypeError(f"Invalid key length: {len(key)}")
    if len(iv) != 32:
        raise argparse.ArgumentTypeError(f"Invalid iv length: {len(iv)}")
    

    bplaintext = bytes.fromhex(plaintext)
    if len(bplaintext) <= 80:
        raise argparse.ArgumentTypeError(f"Invalid plaintext length (lower than 6 blocks): {len(bplaintext)}")
    
    bkey = bytes.fromhex(key)
    biv = bytes.fromhex(iv)
    cipher = AES_128_CBC_encrypt(bplaintext, bkey, biv)
    test(cipher, bkey, biv, 3)
    test(cipher, bkey, biv, 1)
    test(cipher, bkey, biv, 0)
    return

# a good run test to check python3 AES_128_random_access.py -p ffffffffffffffffffffffffffffffffddddddddddddddddddddddddddddddddaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa111111111111111111111111111111112222222222222222222222222222222233333333333333333333333333333333 -k 199494cdea9c646e76015c5bd3ffdaec -iv 199494cdea9c646e76015c5bd3ffdaec
if __name__ == "__main__":
    main()