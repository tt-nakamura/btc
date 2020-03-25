from Transaction import Transaction

sk = 21616604085097315340774341623809954423579083536170398274033280013910110060990

addr1 = '2NGZrVvZG92qGYqzTLjCAewvPZ7JE8S8VxE'
addr2 = 'miENqrEXtuvy32bdbULrU9oGsqqsJhN91s'

tx_id = 0xd50f9933bed2110ee85b3c7a71e5997ded744b7177e6207fac316db5f89e599c
index = 0
amount1 = int(0.00006 * 1e8)
amount2 = int(0.00003 * 1e8)

tx = Transaction(testnet=True)
tx.AddInput(tx_id, index)
tx.AddOutput(amount1, addr1)
tx.AddOutput(amount2, addr2)
tx.sign(0,sk)
print(tx.IsValid())
print(tx.encode().hex())
