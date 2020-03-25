# reference:
#   J. Song, "Programming Bitcoin" (O'Reilly)

import hashlib
import time
import random
import socket
import ECDSA
from varint import *
from murmur3 import *
from io import BytesIO
from BlockHeader import BlockHeader

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'
BIP37_CONSTANT = 0xfba4c795

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4

class BTCNode:
    def __init__(self, host, port=8333, testnet=False):
        if testnet and port==8333: port += 10000
        self.testnet = testnet
        self.socket = socket.socket()
        self.socket.connect((host, port))
        self.stream = self.socket.makefile('rb')
        self.handshake()

    def send(self, command, payload=b''):
        if self.testnet: s = TESTNET_NETWORK_MAGIC
        else:            s = NETWORK_MAGIC
        s += command.ljust(12, b'\x00')
        s += len(payload).to_bytes(4, 'little')
        cs = hashlib.sha256(payload).digest()
        cs = hashlib.sha256(cs).digest()
        s += cs[:4] # checksum
        s += payload
        self.socket.sendall(s)

    def receive(self):
        magic = self.stream.read(4)
        if magic not in (NETWORK_MAGIC, TESTNET_NETWORK_MAGIC):
            raise RuntimeError('bad magic: {}'.format(magic))

        command = self.stream.read(12).strip(b'\x00')
        l = int.from_bytes(self.stream.read(4), 'little')
        checksum = self.stream.read(4)
        payload = self.stream.read(l)
        cs = hashlib.sha256(payload).digest()
        cs = hashlib.sha256(cs).digest()
        if checksum != cs[:4]:
            raise RuntimeError('checksum mismatch')

        return command, payload
        
    def WaitFor(self, *commands):
        while True:
            command, payload = self.receive()
            if command == b'version':
                self.send(b'verack')
            elif command == b'ping':
                self.send(b'pong', payload)
            elif command in commands: break

        return command, payload

    def submit(self, obj):
        self.send(obj.command, obj.encode())

    def fetch(self, *classes):
        cls = {c.command: c for c in classes}
        c,p = self.WaitFor(*cls.keys())
        return cls[c].decode(BytesIO(p))

    def handshake(self,
                  version = 70015,
                  services = 0,
                  timestamp = int(time.time()),
                  receiver_services = 0,
                  receiver_ip = b'\x00\x00\x00\x00',
                  receiver_port = 8333,
                  sender_services = 0,
                  sender_ip = b'\x00\x00\x00\x00',
                  sender_port = 8333,
                  nonce = random.randrange(2**64),
                  user_agent = b'/programmingbitcoin:0.1/',
                  latest_block = 0,
                  relay = False):
        s = version.to_bytes(4, 'little')
        s += services.to_bytes(8, 'little')
        s += timestamp.to_bytes(8, 'little')
        s += receiver_services.to_bytes(8, 'little')
        s += receiver_ip.rjust(6, b'\xff').rjust(16, b'\x00')
        s += receiver_port.to_bytes(2, 'big')
        s += sender_services.to_bytes(8, 'little')
        s += sender_ip.rjust(6, b'\xff').rjust(16, b'\x00')
        s += sender_port.to_bytes(2, 'big')
        s += nonce.to_bytes(8, 'little')
        s += VarintFromInt(len(user_agent))
        s += user_agent
        s += latest_block.to_bytes(4, 'little')
        s += b'\x01' if relay else b'\x00'

        self.send(b'version', s)
        self.WaitFor(b'verack')

    def GetBlockHeaders(self,
                   start_block,
                   end_block=0,
                   version=70015,
                   n_hash=1):
        s = version.to_bytes(4, 'little')
        s += VarintFromInt(n_hash)
        s += start_block.to_bytes(32, 'little')
        s += end_block.to_bytes(32, 'little')

        self.send(b'getheaders', s)

        _, payload = self.WaitFor(b'headers')
        stream = BytesIO(payload)

        n = IntFromVarint(stream)
        headers = []
        for _ in range(n):
            headers.append(BlockHeader.decode(stream))
            if IntFromVarint(stream):
                raise RuntimeError('number of tx must be 0')

        return headers

    def SetFilter(self,
                   addresses,
                   size=30,
                   n_func=5,
                   tweak=90210,
                   flag=1):
        b = bytearray(size) # bloom filter

        for addr in addresses:
            h = ECDSA.Hash160FromAddr(addr)
            for i in range(n_func):
                seed = i*BIP37_CONSTANT + tweak
                j = murmur3(h, seed) % (size<<3)
                b[j>>3] |= 1<<(j&7)

        s = VarintFromInt(size)
        s += b
        s += n_func.to_bytes(4, 'little')
        s += tweak.to_bytes(4, 'little')
        s += flag.to_bytes(1, 'little')

        self.send(b'filterload', s)

    def request(self, keys, data_type):
        dt = data_type.to_bytes(4, 'little')
        s = VarintFromInt(len(keys))
        for k in keys:
            s += dt
            s += k.to_bytes(32, 'little')

        self.send(b'getdata', s)

    def RequestTX(self, keys):
        self.request(keys, TX_DATA_TYPE)
    def RequestBlock(self, keys):
        self.request(keys, BLOCK_DATA_TYPE)
    def RequestFilteredBlock(self, keys):
        self.request(keys, FILTERED_BLOCK_DATA_TYPE)
    def RequestCompactBlock(self, keys):
        self.request(keys, COMPACT_BLOCK_DATA_TYPE)
