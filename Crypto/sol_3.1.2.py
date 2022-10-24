import sys
from string import ascii_uppercase

ciphertext_file = sys.argv[1]
key_file = sys.argv[2]
output_file = sys.argv[3]

ciphertext = ''
key = ''
# strip() remove any leading or trailing whitespace characters
with open(ciphertext_file) as f:
    ciphertext = f.read().strip()

with open(key_file) as f:
    key = f.read().strip()

key_map = {}
for i,let in enumerate(ascii_uppercase):
    key_map[key[i]] = let

plaintext = ''
for char in ciphertext:
    if char in key_map:
        plaintext += key_map[char]
    else:
        plaintext += char

with open(output_file, 'w') as f:
    f.write(plaintext)
