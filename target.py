from BTCNode import BTCNode
from BlockHeader import BlockHeader, NewBits

#seed = 'seed.bitcoin.sipa.be'
seed = 'dnsseed.bluematt.me'
#seed = 'dnsseed.bitcoin.dashjr.org'
#seed = 'seed.bitcoinstats.com'
#seed = 'seed.bitcoin.jonasschnelli.ch'
#seed = 'seed.voskuil.org'

start_block = BlockHeader.genesis()
node = BTCNode(seed)

count = 1
prev_block = start_block
bits = start_block.bits

for _ in range(20):
    headers = node.GetBlockHeaders(prev_block.ID())
    for header in headers:
        if not header.IsValid():
            raise RuntimeError('invalid block')
        if header.prev != prev_block.ID():
            raise RuntimeError('discontinuous block')
        if count % 2016 == 0:
            bits = NewBits(start_block, prev_block)
            start_block = header
            print(bits.hex())
        if header.bits != bits:
            raise RuntimeError('wrong bits')
        prev_block = header
        count += 1
