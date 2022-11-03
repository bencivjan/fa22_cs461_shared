from math import gcd, floor
from functools import reduce
from Crypto.Util import number
from Crypto.PublicKey import RSA
from pbp import decrypt

# Input: N1,...,Nm RSA moduli
#     1: Compute P = ∏Ni using a product tree.
#     2: Compute zi = (P mod Ni^2) for all i using a remainder tree.
# Output: gcd(Ni,zi/Ni) for all i.

# Based on https://facthacks.cr.yp.to/product.html
def product_tree(X):
    result = [X]
    while len(X) > 1:
        X = [reduce(lambda x,y:x*y, X[i*2:(i+1)*2]) for i in range((len(X)+1)//2)]
        result.append(X)
    return result

# Based on https://facthacks.cr.yp.to/batchgcd.html
def batchgcd_faster(X):
    prods = product_tree(X)
    R = prods.pop()
    while prods:
        X = prods.pop()
        R = [R[floor(i/2)] % X[i]**2 for i in range(len(X))]
    return [gcd(r//n,n) for r,n in zip(R,X)]

def get_d(p, q, e):
    totient = (p-1)*(q-1)
    return number.inverse(e,totient)

c = ''
with open('3.2.4_ciphertext.enc.asc') as f:
    c = f.read()
print(c)

with open('moduli.hex') as f:
    e = 65537
    moduli = []
    for line in f:
        moduli.append(int(line, 16))
    print(len(moduli))
    p_list = batchgcd_faster(moduli)
    # print(p_list)
    for i in range(len(p_list)):
        p = p_list[i]
        if p <= 1:
            continue
        N = moduli[i]
        q = N // p
        d = get_d(p, q, e)
        
        try:
            session_key = RSA.construct((N,e,d,p,q))
            # print(session_key)
            # print(c)
            print("Plaintext: ", decrypt(session_key, c))
        except Exception as exc:
            print(i, exc)


# assert product_fast([1,2,3,4,5,6,7,8,9,10]) == 1 * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10
# assert product_fast([3555, 9383, 22, 4, 8887]) == 3555 * 9383 * 22 * 4 * 8887
# assert product_fast([1000, 100, 10, 1, 9338, 736362]) == 1000 * 100 * 10 * 1 * 9338 * 736362

# # example:
# assert remainder_tree(8675309,[11,13,17,19,23]) == [8675309 % p for p in [11,13,17,19,23]]
# print(batchgcd_faster([1909,2923,291,205,989,62,451,1943,1079,2419]))
# # output: [5, 6, 5, 4, 8]

# print("All tests passed")