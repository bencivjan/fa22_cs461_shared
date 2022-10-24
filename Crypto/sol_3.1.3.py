import sys
from Crypto.Cipher import AES

ciphertext_file = sys.argv[1]
key_file = sys.argv[2]
iv_file = sys.argv[3]
output_file = sys.argv[4]

ciphertext = b''
key = b''
iv = b''
with open(ciphertext_file) as f:
    ciphertext = bytes.fromhex(f.read().strip())
with open(key_file) as f:
    key = bytes.fromhex(f.read().strip())
with open(iv_file) as f:
    iv = bytes.fromhex(f.read().strip())

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = cipher.decrypt(ciphertext)

cipher2 = AES.new(key, AES.MODE_CBC, iv)

assert cipher2.encrypt(pt) == ciphertext

with open(output_file, 'w') as f:
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    # pt = cipher.decrypt(ciphertext)
    f.write(pt.decode('utf-8'))
