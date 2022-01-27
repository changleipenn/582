import random
from re import A

from params import p
from params import g

def keygen():
    q = (p-1)/2
    a = random.randint(1,q)
    h = pow(g,a,p)
    sk = a
    pk = h
    return pk,sk

def encrypt(pk,m):
    c1 = 0
    c2 = 0
    q = (p-1)/2
    r = random.randint(1,q)
    c1 = pow(g,r,p)
    c2 = (pow(h,r,p) * (m % p)) % p
    return [c1,c2]

def decrypt(sk,c):
    m = 0
    c1 = c[0]
    c2 = c[1]
    tmp = pow(c1,-sk,p)
    m = (c2 % p * tmp) % p
    return m

print(keygen()[0])
