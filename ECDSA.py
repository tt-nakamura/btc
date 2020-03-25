import hashlib
from random import randrange
from EC_p import EC_p, InvMod
from base58 import *

EC_p.init(
    modulus = 2**256 - 2**32 - 977,
    a = 0,
    b = 7,
    gen_x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    gen_y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
    order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
)

def GenKeys():
    secret_key = randrange(EC_p.order)
    public_key = secret_key * EC_p.generator
    return secret_key, public_key

def sign(signee, secret_key):
    k = randrange(EC_p.order)
    R = k * EC_p.generator
    s = (signee + R.x * secret_key) % EC_p.order
    s = s * InvMod(k, EC_p.order) % EC_p.order
    return (R.x, s)

def verify(signee, signature, public_key):
    r,s = signature
    s_inv = InvMod(s, EC_p.order)
    u,v = signee * s_inv, r * s_inv
    R = u * EC_p.generator + v * public_key
    return R.x == r

def SECFromPubkey(public_key, compress=True):
    p = public_key.x.to_bytes(32, 'big')
    if compress:
        m = b'\x03' if public_key.y & 1 else b'\x02'
    else:
        m = b'\x04'
        p += public_key.y.to_bytes(32, 'big')
    return m+p

def SECFromSecretKey(secret_key, compress=True):
    public_key = secret_key * EC_p.generator
    return SECFromPubkey(public_key, compress)

def PubkeyFromSEC(s):
    x = int.from_bytes(s[1:33], 'big')
    if s[0]==4:
        y = int.from_btyes(s[33:65], 'big')
    else:
        y = EC_p.ysquare(x)
        y = pow(y, (EC_p.modulus + 1)//4, EC_p.modulus)
        if s[0]&1 ^ y&1: y = EC_p.modulus - y
    return EC_p(x,y)

def DERFromSig(signature):
    r,s = signature
    r = r.to_bytes(32, 'big').lstrip(b'\x00')
    s = s.to_bytes(32, 'big').lstrip(b'\x00')
    if r[0] & 0x80: r = b'\x00' + r
    if s[0] & 0x80: s = b'\x00' + s
    d = bytes([2, len(r)]) + r + bytes([2, len(s)]) + s
    return bytes([0x30, len(d)]) + d

def SigFromDER(d):
    i = d[3] + 4
    j = i+2
    k = d[i+1] + j
    r = int.from_bytes(d[4:i], 'big')
    s = int.from_bytes(d[j:k], 'big')
    return (r,s)

def AddrFromHash160(hash160, testnet=False, script=False):
    if script:
        if testnet: s = b'\xc4'
        else:       s = b'\x05'     
    else:
        if testnet: s = b'\x6f'
        else:       s = b'\x00'

    s += hash160
    cs = hashlib.sha256(s).digest()
    cs = hashlib.sha256(cs).digest() # checksum
    s += cs[:4]
    t = s.lstrip(b'\x00')
    s = '1' * (len(s) - len(t))
    s += Base58FromInt(int.from_bytes(t, 'big'))
    return s

def Hash160FromAddr(address):
    i = IntFromBase58(address)
    b = i.to_bytes(25, 'big')
    cs = hashlib.sha256(b[:-4]).digest()
    cs = hashlib.sha256(cs).digest() # checksum
    if cs[:4] != b[-4:]:
        raise RuntimeError('checksum mismatch')

    return b[1:-4]

def GenAddr(compress=True, testnet=False):
    secret_key, public_key = GenKeys()
    s = SECFromPubkey(public_key, compress)
    s = hashlib.sha256(s).digest()
    s = hashlib.new('ripemd160', s).digest()
    address = AddrFromHash160(s, testnet)
    return address, secret_key, public_key
