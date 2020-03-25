from BTCNode import BTCNode
from MerkleBlock import MerkleBlock

#seed = 'testnet-seed.bitcoin.jonasschnelli.ch'
#seed = 'seed.tbtc.petertodd.org'
seed = 'testnet-seed.bluematt.me'
#seed = 'testnet-seed.bitcoin.schildbach.de'
#seed = 'testnet-seed.voskuil.org'

node = BTCNode(seed, testnet=True)

addr = 'miENqrEXtuvy32bdbULrU9oGsqqsJhN91s'
tx_id = 0xd50f9933bed2110ee85b3c7a71e5997ded744b7177e6207fac316db5f89e599c
block_id = 0x17b2bdec7c2942c24948359b096a2ae9c0c8a3248bda36a9983

node.SetFilter([addr])
node.RequestFilteredBlock([block_id])

m = node.fetch(MerkleBlock)
if m.includes(tx_id) and m.IsValid():
    print("proof done")
