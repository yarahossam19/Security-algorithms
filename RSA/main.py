import random
from math import gcd

#Extended Euclidean Algorithm
def  mod_Inv(a, m):
    def EEA(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = EEA(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, y = EEA(a, m)
    if gcd != 1:
        raise ValueError("The inverse does not exist.")
    else:
     return (x % m + m) % m


def modmul(a,b,n):
    return (a*b)%n
def squaremultiply(base, e, mod,group=modmul):
    assert e>0
    res = 1
    binarye = bin(e)[2:]  # Skip the '0b' prefix in the binary representation
    while e!=0:
        if e & 0x1==1:
            res=group(res,base,mod)

        base=group(base,base,mod)
        e = e>>1

    return res

def generate_keypair():
    p = generate_large_prime(2 ** 10, 2 ** 16)
    q = generate_large_prime(2 ** 10, 2 ** 16)
    while p == q:
        p =  generate_large_prime(2 ** 100, 2 ** 160)
        q =  generate_large_prime(2 ** 100, 2 ** 160)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi)
    #Check if e has inverse
    while gcd(e, phi) != 1:
        e = random.randint(2, phi)
    d = mod_Inv(e, phi)
    return (n, e), d, p, q

def generate_large_prime(min_val,max_val):
    num = random.randint(min_val, max_val)
    while not is_prime_fermat(num, 5):
        num = random.randint(min_val, max_val)

    return num

def is_prime_fermat(n, k):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True


def rsa_encrypt(plain_text, public_key):
    n, e = public_key
    cipher_text = []
    for char in plain_text:
        cipher_text.append(squaremultiply(ord(char), e, n))
    return cipher_text

def rsa_decrypt(cipher_text, public_key, private_key,p1,q1):
    n,e=public_key
    dp = private_key % (p1 - 1)
    dq = private_key % (q1- 1)
    cp = mod_Inv(q1,p1)
    cq = mod_Inv(p1,q1)
    decrypted_message =""
    for c in cipher_text:
        xp = c % p1
        xq = c % q1
        yp = squaremultiply(xp, dp, p1)
        yq = squaremultiply(xq, dq, q1)
        y1 = (q1*cp)*yp
        y2 = (p1*cq)*yq
        decrypted_message+=(chr((y1+y2)%n))

    return decrypted_message

# Get user input for the message
message = input("Enter the message to encrypt: ")
# Generate key pair
public_key, private_key, p,q= generate_keypair()
print("Selected p, q:", p, ",", q)
print("Public Key (n, e):", public_key)
print("Private Key (d):", private_key)

# Example encryption using the public key
encrypted_message = rsa_encrypt(message, public_key)
print("Encrypted message:", encrypted_message)

# Example decryption using the private key
decrypted_message = rsa_decrypt(encrypted_message,public_key, private_key,p,q)
print("Decrypted message:", decrypted_message)

