import os
import time
import matplotlib.pyplot as plt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def gcm_speed_test(data):
    key= os.urandom(16)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES128(key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    start_time = time.time()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    encryption_time = time.time() - start_time

    cipher = Cipher(algorithms.AES128(key), modes.GCM(iv,encryptor.tag))
    decryptor = cipher.decryptor()

    start_time = time.time()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    decryption_time = time.time() - start_time

    return encryption_time, decryption_time

def chacha20_poly1305_speed_test(data):
    nonce = os.urandom(16)
    key = os.urandom(32)

    cipher = Cipher(algorithms.ChaCha20(key, nonce), None, backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    start_time = time.time()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    encryption_time = time.time() - start_time

    start_time = time.time()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    decryption_time = time.time() - start_time

    return encryption_time, decryption_time

def run_tests(data_size_mb, num_tests):
    data_size_bytes = data_size_mb * 1024 * 1024

    gcm_enc_times = []
    gcm_dec_times = []
    chacha_enc_times = []
    chacha_dec_times = []

    for _ in range(num_tests):
        data = os.urandom(data_size_bytes)

        gcm_enc_time, gcm_dec_time = gcm_speed_test(data)
        chacha_enc_time, chacha_dec_time = chacha20_poly1305_speed_test(data)

        gcm_enc_times.append(gcm_enc_time)
        gcm_dec_times.append(gcm_dec_time)
        chacha_enc_times.append(chacha_enc_time)
        chacha_dec_times.append(chacha_dec_time)

    return (
        sum(gcm_enc_times) / num_tests,
        sum(gcm_dec_times) / num_tests,
        sum(chacha_enc_times) / num_tests,
        sum(chacha_dec_times) / num_tests,
    )

def plot_results(gcm_enc_times, gcm_dec_times, chacha_enc_times, chacha_dec_times):
    labels = ['GCM En', 'ChaCha20 En','GCM Dec', 'ChaCha20 Dec']

    plt.bar(labels, [gcm_enc_times, chacha_enc_times, gcm_dec_times, chacha_dec_times], color=['blue', 'red', 'blue', 'red'])
    plt.ylabel('Time (seconds)')
    plt.title('Encryption and Decryption Speed Comparison')

    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    plot_path = os.path.join(script_dir, 'encryption_decryption_speed_comparison.png')
    plt.savefig(plot_path)

if __name__ == "__main__":
    data_size_mb = 400
    num_tests = 5

    gcm_enc_time, gcm_dec_time, chacha_enc_time, chacha_dec_time = run_tests(data_size_mb, num_tests)

    print(f"GCM Encryption Time: {gcm_enc_time:.6f} seconds")
    print(f"GCM Decryption Time: {gcm_dec_time:.6f} seconds")
    print(f"ChaCha20-Poly1305 Encryption Time: {chacha_enc_time:.6f} seconds")
    print(f"ChaCha20-Poly1305 Decryption Time: {chacha_dec_time:.6f} seconds")

    plot_results(gcm_enc_time, gcm_dec_time, chacha_enc_time, chacha_dec_time)
