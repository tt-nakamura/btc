ENDIAN = 'little'

def IntFromVarint(stream):
    i = stream.read(1)[0]
    if i < 0xfd: return i
    if   i==0xfd: n=2
    elif i==0xfe: n=4
    else:         n=8
    return int.from_bytes(stream.read(n), ENDIAN)

def VarintFromInt(i):
    if i < 0xfd: return bytes([i])
    if i < 0x10000: n,p = 2,b'\xfd'
    elif i < 0x100000000: n,p = 4,b'\xfe'
    elif i < 0x10000000000000000: n,p = 8,b'\xff'
    else: raise ValueError('i too large: {}'.format(i))
    return p + i.to_bytes(n, ENDIAN)
