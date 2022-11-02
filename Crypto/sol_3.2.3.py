import urllib.request, urllib.error
from math import ceil

def get_status(u):
    try:
        resp = urllib.request.urlopen(u)
        return 0
    except urllib.error.HTTPError as e:
        return e.code

url_base = 'http://172.22.159.75:8080/mp3/fa22_cs461_bcivjan2/?'
ciphertext = ''
with open('/Users/bencivjan/Desktop/fa22_cs461_bcivjan2/Crypto/3.2.3_ciphertext.hex') as f:
    ciphertext = f.read().strip()

# for block in range(1,2):#len(ciphertext)):
text = ''

for block in range(1, ceil(len(ciphertext) / 32)+1):
    pad = ''
    G = [0 for x in range(16)] # equal to 0x10 ^ i in order

    for byte in range(16):
        print(G)
        pad = ''
        xor_val = 0xf
        for j in range(16-byte, 16):
            pad += format(xor_val ^ G[j], '02x')
            xor_val -= 1

        for i in range(256):
            end_idx = -(32*(block-1)) if block-1 > 0 else 99999999
            ct_mod = ciphertext[:-(32*block + 2*(byte+1))] + format(i, '02x') + pad + ciphertext[-(32*block + 2*byte - len(pad)) : end_idx]
            status = get_status(url_base + ct_mod)
            if status == 404 or (byte == 9 and status == 0 and block == 1):
                pt = 0x10 ^ i ^ int(ciphertext[-(32*block + 2*(byte+1)) : -(32*block + 2*byte)], 16)
                text = chr(pt) + text
                G[-(byte+1)] = 0x10 ^ i
                print(status, format(i, '02x'))

print(text)

get_status(f'http://172.22.159.75:8080/mp3/fa22_cs461_bcivjan2/?{ciphertext}')

# inv xor 0xfa = 0x10 -> plaintext C2,15 = 
# 
# ciphertext blocks are 16 bytes