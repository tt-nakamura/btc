# reference:
#   J. Song, "Programming Bitcoin" (O'Reilly)

import hashlib
from BlockHeader import BlockHeader
from varint import *

class MerkleBlock(BlockHeader):
    command = b'merkleblock'

    @classmethod
    def decode(cls, stream):
        self = super().decode(stream)
        self.total = int.from_bytes(stream.read(4), 'little')
        self.hashes = []
        n = IntFromVarint(stream)
        for _ in range(n):
            self.hashes.append(stream.read(32))

        self.ids = [int.from_bytes(h, 'little') for h in self.hashes]
        n = IntFromVarint(stream)
        self.flags = int.from_bytes(stream.read(n), 'little')
        return self

    def includes(self, tx_id):
        return tx_id in self.ids

    def IsValid(self):
        if not super().IsValid(): return False
        r = MerkleRoot(self.total, self.hashes, self.flags)
        return int.from_bytes(r, 'little') == self.root


def MerkleRoot(n, hashes, flags, func=None):
    if func is None:
        func = lambda x: hashlib.sha256(
            hashlib.sha256(x).digest()).digest()

    i,j,node = 0,0,[[None]*n]
    while n>1:
        i,n = i+1,(n+1)>>1
        node.append([None]*n)

    while node[-1][0] is None:
        if i==0:
            node[i][j] = hashes.pop(0)
            i,j = i+1,j>>1
            flags >>= 1
        else:
            a = node[i-1][j<<1] 
            if a is None:
                if flags&1:
                    i,j = i-1,j<<1
                else:
                    node[i][j] = hashes.pop(0)
                    i,j = i+1,j>>1
                flags >>= 1
            elif (j<<1)+1 < len(node[i-1]):
                b = node[i-1][(j<<1)+1]
                if b is None:
                    i,j = i-1,(j<<1)+1
                else:
                    node[i][j] = func(a+b)
                    i,j = i+1,j>>1
            else:
                node[i][j] = func(a+a)
                i,j = i+1,j>>1

    if len(hashes):
        raise RuntimeError('hashes not exhausted')
    if flags:
        raise RuntimeError('flags not exhausted')

    return node[-1][0]
