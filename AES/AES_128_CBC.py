import argparse
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
import binascii

def pad_text(text):
    text = text + ((16 - len(text) %16) * b'\0')
    return text

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
    
def AES_128_CBC_encrypt(plaintext, key, iv):
    # Create an AES-128-ECB cipher object
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    encryptor = cipher.encryptor()

    #pad plaintext to be a multiple of 16 bytes
    plaintext = pad_text(plaintext)

    #cut plaintext into 16 byte blocks and loop through them
    print("--------------------------Encrypt----------------------------")
    print("Processing Block:", plaintext[0:16].hex())
    xor_block = byte_xor(iv, plaintext[0:16])
    ct = encryptor.update(xor_block)
    blockholder = ct
    print("Cipher Text:", ct.hex())
    print("-------------------------------------------------------------")

    for i in range(16, len(plaintext), 16):
        print("Processing Block:", plaintext[i:i+16].hex())
        xor_block = byte_xor(ct, plaintext[i:i+16])
        ct = encryptor.update(xor_block)
        blockholder += ct
        print("Cipher Text:", ct.hex())
        print("-------------------------------------------------------------")

    return blockholder

def AES_128_CBC_decrypt(ciphertext, key, iv):
    # Create an AES-128-ECB cipher object
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    depcryptor = cipher.decryptor()

    #cut plaintext into 16 byte blocks and loop through them
    print("----------------------Decrypt---------------------------------")
    print("Processing Block:", ciphertext[0:16].hex())
    pt = depcryptor.update( ciphertext[0:16])
    xor_block = byte_xor(iv, pt[0:16])
    blockholder = xor_block
    print("Plain Text:", xor_block.hex())
    print("--------------------------------------------------------------")

    for i in range(16, len(ciphertext), 16):
        print("Processing Block:", ciphertext[i:i+16].hex())
        pt = depcryptor.update(ciphertext[i:i+16])
        xor_block = byte_xor(pt, ciphertext[i-16:i])
        blockholder += xor_block
        print("Plain Text:", xor_block.hex())
        print("-------------------------------------------------------------")

    return blockholder

def test(text, key, iv):
    #TEST1:  feed result of encryption into decryption and compare to original plaintext
    pad_len = (16 - len(text) %16)
    ct=AES_128_CBC_encrypt(text, key, iv)
    pt=AES_128_CBC_decrypt(ct, key, iv)
    print("\n============== TEST1 FEEDING RESULT OF ENCRYPTION TO DECRYTPION =================")
    print("Original Plaintext   :", text.hex())
    print("Ciphertext           :", ct.hex())
    pt = pt[:-pad_len] #remove pad from plaintext
    print("Decrypted Ciphertext :", pt.hex()) 
    print("============================== END OF TEST 1 ====================================\n")
    print("\n================== TEST2 COMPARE WITH MODULES AES 128 CBC =====================")
    cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    text = pad_text(text)
    ct2 = encryptor.update(text) + encryptor.finalize()
    print("Original Plaintext             : ", text.hex())
    print("my cipher text encryption      : ", ct.hex())
    print("Cryptography module encryption : ", ct2.hex())
    print("============================== END OF TEST 2 ====================================\n")
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
    if len(plaintext) == 0:
        raise argparse.ArgumentTypeError(f"Invalid plaintext length: {len(plaintext)}")

    bplaintext = bytes.fromhex(plaintext)
    bkey = bytes.fromhex(key)
    biv = bytes.fromhex(iv)

    test(bplaintext, bkey, biv)
    return

# a good run test to check python3 AES_128_random_acces.py -p ffffffffffffffffffffffffffffffffddddddddddddddddddddddddddddddddaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11111111111111111111111111 -k 199494cdea9c646e76015c5bd3ffdaec -iv 199494cdea9c646e76015c5bd3ffdaec
if __name__ == "__main__":
    main()