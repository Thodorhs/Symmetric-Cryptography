import argparse
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from AES_128_CBC import byte_xor

def GCM_random_access(ciphertext, key, iv, index):
    if index < 0:
        raise argparse.ArgumentTypeError(f"Invalid index: {index}")
    
    # Create an AES-128-ECB cipher object
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    encryptor = cipher.encryptor()
    en = encryptor.update(iv)
    
    i = index * 16
    print("Random Access for Block:", ciphertext[i:i+16].hex(), "at index:", index)

    xor_block = byte_xor(ciphertext[i:i+16], en)
    
    print("Plain Text:", xor_block.hex())

def main():
    parser = argparse.ArgumentParser(description='Decrypt a block from ciphertext')
    parser.add_argument('ciphertext', help='The ciphertext as bytes')
    parser.add_argument('key', help='The key as bytes')
    parser.add_argument('iv', help='The IV as bytes')
    parser.add_argument('block_index', type=int, help='The index of the block to decrypt')

    args = parser.parse_args()

    ciphertext = bytes.fromhex(args.ciphertext)
    key = bytes.fromhex(args.key)
    iv = bytes.fromhex(args.iv)

    GCM_random_access(ciphertext, key, iv, args.block_index)

if __name__ == "__main__":
    main()