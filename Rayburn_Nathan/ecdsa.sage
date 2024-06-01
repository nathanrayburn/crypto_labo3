import hashlib

#Useful constants
alpha = 13
beta = 17

# Hashes the message with SHA256 and casts the result into an integer.
def h(m):
    return int(hashlib.sha256(m).hexdigest(),16)

# Signs the message m using the point <G>
# <G> has to be a point on an elliptic curve of order <n>
# <a> is the ECDSA private key
# <ctr> is a counter that is used for k so that we are sure that it is not repeated. Otherwise: crazy attack!
# Returns the ECDSA signature and an updated counter so that we are sure it is not repeated
def sign(G, n, a, ctr, m):
    ctr = alpha*ctr+beta %n #increase counter so that k is not repeated!
    (x1,y1) = (ctr*G).xy()
    F = Integers(n)
    r = F(x1) 
    return(r, (F(h(m)) +a * r) / F(ctr), ctr)

def params():
    p256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a256 = p256 - 3
    b256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    E = EllipticCurve(GF(p256), [a256, b256])
    G = E(gx, gy)
    return (G, E, n)

def verify(m, A, r, s, G, n):
    r = ZZ(r) #To avoid bugs with the following checks
    s = ZZ(s)
    if A == 0:
        return False
    if n*A != 0:
        return False
    if r <= 0 or r >= n:
        return False
    if s <= 0 or s >= n:
        return False
    F = Integers(n)
    r = F(r)
    s = F(s)
    u1 = F(h(m))/s
    u2 = r/s
    return r.lift() == (u1.lift()*G+u2.lift()*A)[0]

def keyGen(G, n):
    a = ZZ.random_element(n)
    A = a*G
    return (a, A)

(G, E, n) = params()


ctr = ZZ.random_element(n)
m1 = b"Welcome to the CRY class"
m2 = b"We will do maths, maths, and maths!"
mchall = b"I'm taking over the CRY course. No more maths!" #challenge to sign
(a, A) = keyGen(G, n)
(r1, s1, ctr) = sign(G, n, a, ctr, m1)
(r2, s2, ctr) = sign(G, n, a, ctr, m2)
