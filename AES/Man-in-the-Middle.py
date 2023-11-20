from AES_128_CBC import parse_hexadecimal, AES_128_CBC_encrypt, AES_128_CBC_decrypt, byte_xor
import random

def modify_cipher(ct):
    c1=ct[0:16]
    c2=16*b'\0'
    return c1+c2+c1

def random3blocks():
    #create a random 3 blocks of 128 bits from the wordlist_1000.txt
    with open("wordlist_1000.txt", 'r') as file:
        words = file.read().splitlines()
    random_words = random.sample(words, min(len(words), 20))
    random_string = ''.join(random_words)
    truncated_string = random_string[:48]
    #print("Random String:", truncated_string)
    return truncated_string

def man_in_the_middle():
    text=random3blocks() #random 3 blocks of 128 bits
    btext=bytes(text, 'utf-8')
    bkey_iv=parse_hexadecimal("199494cdea9c646e76015c5bd3ffdaec")
    ct=AES_128_CBC_encrypt(btext, bkey_iv, bkey_iv)
    ct_mod=modify_cipher(ct) #modify the cipher text C1 0 C1
    pt=AES_128_CBC_decrypt(ct_mod, bkey_iv, bkey_iv)

    key=byte_xor(pt[0:16], pt[32:48]) # XOR of PT1 and PT3 blocks

    print("Key                  :", bkey_iv.hex())
    print("Random Plain Text    :", text,"Length:", len(text))
    print("Plain Text in Hex    :", btext.hex())
    print("Cipher Text          :", ct[:48].hex())
    print("Modified Cipher Text :", ct_mod.hex())
    print("Decrypted Plain Text :", pt.hex())
    print("XOR of PT1 and PT3   :", key.hex())
    return 

def main():
    man_in_the_middle()
    return 

if __name__ == "__main__":
    main() 