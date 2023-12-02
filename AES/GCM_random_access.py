import argparse
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from AES_128_CBC import byte_xor

def GCM_random_access(ciphertext, key, iv, index):
    if index < 0:
        raise argparse.ArgumentTypeError(f"Invalid index: {index}")
    print("iv                                : ", iv.hex())
    #add counter to ls 64 bits of iv
    iv = iv[:-4] + (index+2).to_bytes(4, byteorder='big')
    print("iv after adding 64bits of counter : ", iv.hex())
    # Create an AES-128-ECB cipher object
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    encryptor = cipher.encryptor()
    en = encryptor.update(iv)
    print("en:", en.hex())
    i = index * 16
    print("Random Access for Block:", ciphertext[i:i+16].hex(), "at index:", index)

    xor_block = byte_xor(ciphertext[i:i+16], en)
    
    print("Plain Text:", xor_block.hex())

def main():
    parser = argparse.ArgumentParser(description='Decrypt a block from ciphertext')
    parser.add_argument("-c",  required=True, help="The ciphertext, encoded in hexadecimal format")
    parser.add_argument("-k",  required=True, help="The key, encoded in hexadecimal format")
    parser.add_argument("-iv", required=True, help="The IV, encoded in hexadecimal format")
    parser.add_argument("-i", type=int, required=True, help="The index of the block to decrypt")

    args = parser.parse_args()

    ciphertext = bytes.fromhex(args.c)
    key = bytes.fromhex(args.k)
    iv = bytes.fromhex(args.iv)
    print("ciphertext:", ciphertext.hex())
    print("key:", key.hex())

    GCM_random_access(ciphertext, key, iv, args.i)

if __name__ == "__main__":
    main()