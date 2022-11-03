from Crypto.Util import number
# from math import gcd

# b1 and b2 are 1024 bitstring collisions generated by fastcoll
def lenstra(b1, b2):
    e = 65537
    while True:
        print("Trying new primes")
        p1 = number.getPrime(500)
        p2 = number.getPrime(500)
        while (number.GCD(p1 - 1, e) != 1):
            p1 = number.getPrime(500)
        while (number.GCD(p2 - 1, e) != 1):
            p2 = number.getPrime(500)

        print("Calculated primes")
        b0 = getCRT(b1*(2**1024), b2*(2**1024), p1, p2)
        print("Calculated CRT")
        k = 0
        while True:
            b = b0 + k * p1 * p2
            q1 = (b1*(2**1024) + b) // p1
            q2 = (b2*(2**1024) + b) // p2

            if (
                number.isPrime(q1) and
                number.isPrime(q2) and
                number.GCD(q1 - 1, e) == 1 and
                number.GCD(q2 - 1, e) == 1
            ):
                print(p1, p2, q1, q2)
                n1 = b1*(2**1024) + b
                n2 = b2*(2**1024) + b
                return (n1,n2,p1,p2,q1,q2)
            if number.size(b) >= 1024:
                print("Size b should be less than 1024: ", number.size(b))
                break
            k += 1
    return -1

# b1_exp = b1*21024
# b2_exp = b2*21024
def getCRT(b1_exp, b2_exp, p1, p2):
    N = p1 * p2
    invOne = number.inverse(p2, p1)
    invTwo = number.inverse(p1, p2)
    return -(b1_exp * invOne * p2 + b2_exp * invTwo * p1) % N

f1 = open('mod_col1', 'rb')
f2 = open('mod_col2', 'rb')
b1 = int(f1.read().hex()[512:], 16)
b2 = int(f2.read().hex()[512:], 16)

print("Running Lenstra with mod_col1 and mod_col2...")
print(lenstra(b1, b2))