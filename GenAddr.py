from EC_p import EC_p
from ECDSA import GenAddr

addr,sk,pk = GenAddr(testnet=True)

print(EC_p.order)
print(EC_p.generator.x)
print(EC_p.generator.y)

print(sk)
print(pk.x)
print(pk.y)
print(addr)
