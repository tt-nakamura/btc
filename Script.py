from varint import *
from opcode import *
from io import BytesIO

def decode(stream, length=None):
    if length is None: length = IntFromVarint(stream)
    codes = []
    i = 0
    while i<length:
        b = stream.read(1)
        if not b: break
        c = b[0]
        i += 1
        if c >= 1 and c < OP_PUSHDATA1:
            codes.append(stream.read(c))
            i += c
        elif c == OP_PUSHDATA1:
            l = stream.read(1)[0]
            codes.append(stream.read(l))
            i += l+1
        elif c == OP_PUSHDATA2:
            l = int.from_bytes(stream.read(2), 'little')
            codes.append(stream.read(l))
            i += l+2
        else:
            codes.append(c)
            
    if i>length: raise RuntimeError('invalid script')

    return codes

def encode(codes, length=True):
    s = b''
    for c in codes:
        if type(c) == int:
            s += bytes([c])
        else:
            l = len(c)
            if l < OP_PUSHDATA1:
                s += bytes([l])
            elif l < 256:
                s += bytes([OP_PUSHDATA1, l])
            elif l < 520:
                s += bytes([OP_PUSHDATA2])
                s += l.to_bytes(2, 'little')
            else:
                raise RuntimeError('failed to encode script')

            s += c

    if length: s = VarintFromInt(len(s)) + s
    return s

def is_p2sh(codes):
    return(len(codes) == 3 and
           codes[0] == OP_HASH160 and
           type(codes[1]) == bytes and
           len(codes[1]) == 20 and
           codes[2] == OP_EQUAL)

def is_p2pkh(codes):
    return(len(codes) == 5 and
           codes[0] == OP_DUP and
           codes[1] == OP_HASH160 and
           type(codes[2]) == bytes and
           len(codes[2]) == 20 and
           codes[3] == OP_EQUALVERIFY and
           codes[4] == OP_CHECKSIG)

def is_p2wpkh(codes):
    return(len(codes) == 2 and
           codes[0] == OP_0 and
           type(codes[1]) == bytes and
           len(codes[1]) == 20)

def execute(codes, *args):
    stack = []
    while codes:
        c = codes.pop(0)
        if type(c) == int:
            f = OP_FUNCTIONS[c]
            if c in OP_2ARG: y = f(stack, args[0])
            else:            y = f(stack)
            if not y:
                raise RuntimeError('bad opcode:', c)
        else:
            stack.append(c)
            if is_p2sh(codes):
                codes.pop(0)
                if not op_hash160(stack): return False
                stack.append(codes.pop(0))
                codes.pop(0)
                if not op_equalverify(stack): return False
                codes += decode(BytesIO(c), length=len(c))

    return len(stack) and stack[-1]

def p2pkh(hash160):
    return [OP_DUP,
            OP_HASH160,
            hash160,
            OP_EQUALVERIFY,
            OP_CHECKSIG]

def p2sh(hash160):
    return [OP_HASH160,
            hash160,
            OP_EQUAL]
