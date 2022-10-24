import sys
from Crypto.Cipher import AES

def find_keys():
    ciphertext_file = '3.1.4_aes_weak_ciphertext.hex'
    out_file = '3.1.4_plaintext.txt'

    ciphertext = b''
    key = '0b' + '0'*251
    iv = b'\x00' * 16
    with open(ciphertext_file) as f:
        ciphertext = bytes.fromhex(f.read().strip())

    with open(out_file, 'w') as f:
        for i in range(2**5):
            # print(type(int(key + format(i, '05b'), 2).to_bytes(32, 'big')))
            cipher = AES.new(int(key + format(i, '05b'), 2).to_bytes(32, 'big'), AES.MODE_CBC, iv)
            pt = cipher.decrypt(ciphertext)
            f.write('\n' + format(int(key + format(i, '05b'), 2), '064x') + '\n' + str(pt) + '\n')

def test_key(hex: str):
    key = bytes.fromhex(hex)
    ciphertext = b''
    iv = b'\x00' * 16

    with open('3.1.4_aes_weak_ciphertext.hex') as f:
        ciphertext = bytes.fromhex(f.read().strip())

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ciphertext)

    print(pt.decode('utf-8'))

test_key('000000000000000000000000000000000000000000000000000000000000001d')
