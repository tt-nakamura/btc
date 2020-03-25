# reference:
#   J. Song, "Programming Bitcoin" (O'Reilly)

import hashlib
from io import BytesIO

TWO_WEEKS = 14*24*60*60
TARGET_MAX = 0xffff * 256**(0x1d - 3)

class BlockHeader:
    def __init__(self, version, prev, root, time, bits, nonce):
        self.version = version
        self.prev = prev
        self.root = root
        self.time = time
        self.bits = bits
        self.nonce = nonce

    def encode(self):
        s = self.version.to_bytes(4, 'little')
        s += self.prev.to_bytes(32, 'little')
        s += self.root.to_bytes(32, 'little')
        s += self.time.to_bytes(4, 'little')
        s += self.bits
        s += self.nonce.to_bytes(4, 'little')
        return s

    @classmethod
    def decode(cls, stream):
        version = int.from_bytes(stream.read(4), 'little')
        prev = int.from_bytes(stream.read(32), 'little')
        root = int.from_bytes(stream.read(32), 'little')
        time = int.from_bytes(stream.read(4), 'little')
        bits = stream.read(4)
        nonce = int.from_bytes(stream.read(4), 'little')
        return cls(version, prev, root, time, bits, nonce)

    @classmethod
    def genesis(cls, testnet=False):
        s = '01' + '0'*70
        s += '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a'
        if testnet: s += 'dae5494dffff001d1aa4ae18'
        else:       s += '29ab5f49ffff001d1dac2b7c'
        return cls.decode(BytesIO(bytes.fromhex(s)))

    def ID(self):
        b = hashlib.sha256(self.encode()).digest()
        b = hashlib.sha256(b).digest()
        return int.from_bytes(b, 'little')

    def target(self):
        t = int.from_bytes(self.bits[:-1], 'little')
        t <<= (self.bits[-1] - 3)<<3
        return t

    def difficulty(self):
        return TARGET_MAX/self.target()

    def IsValid(self):
        return self.ID() < self.target()


def NewBits(block1, block2):
    t = (block2.time - block1.time) / TWO_WEEKS
    t = min(max(t, 0.25), 4) * block2.target()
    t = min(int(t), TARGET_MAX) # new target
    b = t.to_bytes(32, 'little').rstrip(b'\x00')
    if b[-1] & 0x80:
        return b[-2:] + bytes([0, len(b)+1])
    else:
        return b[-3:] + bytes([len(b)])
