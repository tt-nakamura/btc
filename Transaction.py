# reference:
#   J. Song, "Programming Bitcoin" (O'Reilly)

import hashlib
import Script
import ECDSA
from urllib.request import urlopen
from io import BytesIO
from varint import *

#import ssl
#ssl._create_default_https_context = ssl._create_unverified_context

#URL_MAINNET = 'https://blockchain.info/tx/'
#URL_TESTNET = 'https://testnet.blockchain.info/tx/'
#URL_SUFFIX = '?format=hex'

URL_MAINNET = 'http://mainnet.programmingbitcoin.com/tx/'
URL_TESTNET = 'http://testnet.programmingbitcoin.com/tx/'
URL_SUFFIX = '.hex'

SIGHASH_ALL = 1 
SIGHASH_NONE = 2 
SIGHASH_SINGLE = 3 
SIGHASH_ANYONECANPAY = 128

class TxInput:
    def __init__(self, prev, index, script=[], sequence=0xffffffff):
        self.prev = prev
        self.index = index
        self.script = script
        self.sequence = sequence

    def encode(self):
        s = self.prev.to_bytes(32, 'little')
        s += self.index.to_bytes(4, 'little')
        s += Script.encode(self.script)
        s += self.sequence.to_bytes(4, 'little')
        return s

    @classmethod
    def decode(cls, stream):
        prev = int.from_bytes(stream.read(32), 'little')
        index = int.from_bytes(stream.read(4), 'little')
        script = Script.decode(stream)
        sequence = int.from_bytes(stream.read(4), 'little')
        return cls(prev, index, script, sequence)

    def prev_out(self, testnet=False):
        tx = Transaction.fetch(self.prev, testnet)
        return tx.outs[self.index]


class TxOutput:
    def __init__(self, amount, script):
        self.amount = amount
        self.script = script

    def encode(self):
        s = self.amount.to_bytes(8, 'little')
        s += Script.encode(self.script)
        return s

    @classmethod
    def decode(cls, stream):
        amount = int.from_bytes(stream.read(8), 'little')
        script = Script.decode(stream)
        return cls(amount, script)

    def HasAddr(self, address):
        if Script.is_p2sh(self.script): h = self.script[1]
        elif Script.is_p2pkh(self.script): h = self.script[2]
        elif Script.is_p2wpkh(self.script): h = self.script[1]
        else: return False
        return h == ECDSA.Hash160FromAddr(address)


class Transaction:
    command = b'tx'
    cache = { }

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if not fresh and tx_id in cls.cache:
            return cls.cache[tx_id]

        url = URL_TESTNET if testnet else URL_MAINNET
        url += '{:064x}'.format(tx_id) + URL_SUFFIX

        u = urlopen(url).read().decode().strip()
        u = bytes.fromhex(u)

        tx = cls.decode(BytesIO(u), testnet)
        if tx.ID() != tx_id:
            raise RuntimeError('failed to fetch Tx: {}'.format(tx_id))
 
        cls.cache[tx_id] = tx
        return tx

    def __init__(self, version=1, ins=[], outs=[], locktime=0,
                 testnet=False, segwit=False):
        self.version = version
        self.ins = ins
        self.outs = outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit

    def AddInput(self, prev, index):
        self.ins.append(TxInput(prev, index))

    def AddOutput(self, amount, address):
        h = ECDSA.Hash160FromAddr(address)
        if address[0] in '1mn': script = Script.p2pkh(h)
        elif address[0] in '23': script = Script.p2sh(h)
        else: raise RuntimeError('unknown pay type')

        self.outs.append(TxOutput(amount, script))

    def encode(self):
        s = self.version.to_bytes(4, 'little')
        if self.segwit: s += b'\x00\x01'
        s += VarintFromInt(len(self.ins))
        for tx_in in self.ins:
            s += tx_in.encode()

        s += VarintFromInt(len(self.outs))
        for tx_out in self.outs:
            s += tx_out.encode()

        if self.segwit:
            for tx_in in self.ins:
                s += bytes([len(tx_in.witness)])
                for item in tx_in.witness:
                    if type(item) == int:
                        s += bytes([item])
                    else:
                        s += VarintFromInt(len(item)) + item

        s += self.locktime.to_bytes(4, 'little')
        return s

    @classmethod
    def decode(cls, stream, testnet=False):
        version = int.from_bytes(stream.read(4), 'little')
        segwit = (stream.read(1) == b'\x00')
        if not segwit: stream.seek(4)
        elif stream.read(1) != b'\x01':
            raise RuntimeError('invalid segwit flag')

        ins,outs = [],[]

        n_in = IntFromVarint(stream)
        for _ in range(n_in):
            ins.append(TxInput.decode(stream))

        n_out = IntFromVarint(stream)
        for _ in range(n_out):
            outs.append(TxOutput.decode(stream))

        if segwit:
            for tx_in in ins:
                n_items = IntFromVarint(stream)
                items = []
                for _ in range(n_items):
                    item_len = IntFromVarint(stream)
                    if item_len == 0: item = 0
                    else: item = stream.read(item_len)
                    items.append(item)
                tx_in.witness = items

        locktime = int.from_bytes(stream.read(4), 'little')
        return cls(version, ins, outs, locktime, testnet, segwit)

    def ID(self):
        segwit, self.segwit = self.segwit, False
        b = hashlib.sha256(self.encode()).digest()
        b = hashlib.sha256(b).digest()
        self.segwit = segwit
        return int.from_bytes(b, 'little')

    def fee(self):
        f = 0
        for tx_in in self.ins:
            f += tx_in.prev_out(self.testnet).amount
        for tx_out in self.outs:
            f -= tx_out.amount
        return f

    def signee(self, index, redeem_script=None):
        s = self.version.to_bytes(4, 'little')
        s += VarintFromInt(len(self.ins))
        for i,tx_in in enumerate(self.ins):
            if i!=index: t = []
            elif redeem_script: t = redeem_script
            else: t = tx_in.prev_out(self.testnet).script
            s += TxInput(
                prev = tx_in.prev,
                index = tx_in.index,
                script = t,
                sequence = tx_in.sequence
            ).encode()

        s += VarintFromInt(len(self.outs))
        for tx_out in self.outs:
            s += tx_out.encode()

        s += self.locktime.to_bytes(4, 'little')
        s += SIGHASH_ALL.to_bytes(4, 'little')
        s = hashlib.sha256(s).digest()
        s = hashlib.sha256(s).digest()
        return int.from_bytes(s, 'big')

    def IsValid(self):
        if len(self.ins) == 0: return False
        if self.fee() < 0: return False
        for i,tx_in in enumerate(self.ins):
            prev_out = tx_in.prev_out(self.testnet)
            if Script.is_p2sh(prev_out.script):
                c = tx_in.script[-1]
                r = Script.parse(BytesIO(c), length=len(c))
                z = self.signee(i,r)
            else: z = self.signee(i)

            s = tx_in.script + prev_out.script
            try: Script.execute(s,z)
            except: return False

        return True

    def sign(self, index, secret_key):
        sec = ECDSA.SECFromSecretKey(secret_key)
        z = self.signee(index)
        sig = ECDSA.sign(z, secret_key)
        sig = ECDSA.DERFromSig(sig)
        sig += bytes([SIGHASH_ALL])
        self.ins[index].script = [sig, sec]

    def IsCoinbase(self):
        return (len(self.ins)==1 and
                self.ins[0].prev == b'\x00'*32 and
                self.ins[0].index == 0xffffffff)

    def CoinbaseHeight(self):
        return int.from_bytes(self.ins[0].script[0], 'little')
