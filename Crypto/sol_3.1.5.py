import sys

ciphertext_file = sys.argv[1]
key_file = sys.argv[2]
modulo_file = sys.argv[3]
output_file = sys.argv[4]

ciphertext = b''
d = b''
n = b''
with open(ciphertext_file) as f:
    ciphertext = int(f.read().strip(), 16)
with open(key_file) as f:
    d = int(f.read().strip(), 16)
with open(modulo_file) as f:
    n = int(f.read().strip(), 16)

pt = pow(ciphertext, d, n)

with open(output_file, 'w') as f:
    f.write(format(pt, 'x'))
