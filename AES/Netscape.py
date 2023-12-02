import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import multiprocessing as mp

def try_decrypt(ciphertext, key, iv, tag):
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        # Verify the tag to check if decryption was successful
        decryptor.verify(tag)
        return plaintext
    except:
        return None
    
def process_key(i, j, estimated_time, time_diff, millisecs, ciphertext, tag):
    for pid in range(i,j):
        seed = (estimated_time + time_diff) * 0x68793435382d63727970746f + pid * 0x677261706879 + millisecs
        r = random.Random(seed)
        key = r.randbytes(16)
        iv = r.randbytes(12)

        plaintext = try_decrypt(ciphertext, key, iv, tag)
        if plaintext is not None:
            print(f"Key found: {key.hex()}")
            print(f"IV found: {iv.hex()}")
            print(f"Decrypted Text: {plaintext.decode('utf-8')}")
            return True
    
def main():
    parser = argparse.ArgumentParser(description='AES-128-GCM Decryption with Brute Force')
    parser.add_argument('-d', '--estimated_time', type=int, help='Estimated encryption time in Unix format')
    parser.add_argument('-c', '--ciphertext', type=bytes.fromhex, help='Ciphertext to be cracked in hex format')
    parser.add_argument('-t', '--tag', type=bytes.fromhex, help='Tag of the ciphertext in hex format')
    args = parser.parse_args()

    estimated_time = args.estimated_time
    ciphertext = args.ciphertext
    tag = args.tag
    # Iterate over the time range and possible seed values
    for time_diff in range(-60, 61):
        for millisecs in range(1000):
            p1 = mp.Process(target=process_key, args=(0, 2000, estimated_time, time_diff, millisecs, ciphertext, tag))
            p2 = mp.Process(target=process_key, args=(2000, 4000, estimated_time, time_diff, millisecs, ciphertext, tag))
            p3 = mp.Process(target=process_key, args=(4000, 6000, estimated_time, time_diff, millisecs, ciphertext, tag))
            p4 = mp.Process(target=process_key, args=(6000, 8000, estimated_time, time_diff, millisecs, ciphertext, tag))
            p5 = mp.Process(target=process_key, args=(8000, 10000, estimated_time, time_diff, millisecs, ciphertext, tag))
            p1.start()
            p2.start()
            p3.start()
            p4.start()
            p5.start()
            p1.join()
            p2.join()
            p3.join()
            p4.join()
            p5.join()
            if p1.exitcode == 1 or p2.exitcode == 1 or p3.exitcode == 1 or p4.exitcode == 1 or p5.exitcode == 1:
                return   
    
    print("Key not found within the specified time range.")

if __name__ == "__main__":
    main()
