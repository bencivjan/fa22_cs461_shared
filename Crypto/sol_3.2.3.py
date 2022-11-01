import urllib.request, urllib.error

def get_status(u):
    try:
        resp = urllib.request.urlopen(u)
        return 0
    except urllib.error.HTTPError as e:
        return e.code

url_base = 'http://172.22.159.75:8080/mp3/fa22_cs461_bcivjan2/?'
ciphertext = ''
with open('3.2.3_ciphertext.hex') as f:
    ciphertext = f.read().strip()

# for block in range(1,2):#len(ciphertext)):
text = ''
pad = ''
G = [0 for x in range(16)] # equal to 0x10 ^ i in order
for byte in range(16):
    print(G)
    for i in range(256):
        status = get_status(url_base + ciphertext[:-(16 + 2*(byte+1))] + format(i, '02x') + pad + ciphertext[-(16 + 2*byte - len(pad)):])
        if status == 404:
            pt = 0x10 ^ i ^ int(ciphertext[-(16 + 2*(byte+1)) : -(16 + 2*byte)], 16)
            text = chr(pt) + text
            G[-(byte+1)] = 0x10 ^ i
            print(status, format(i, '02x'))
    pad = ''
    for j in range(16, 15-byte, -1):
        pad = format(j ^ G[j-1], '02x') + pad
        # else:
        #     print(status)
print(text)

get_status(f'http://172.22.159.75:8080/mp3/fa22_cs461_bcivjan2/?{ciphertext}')

# inv xor 0xfa = 0x10 -> plaintext C2,15 = 
# 
# ciphertext blocks are 16 bytes