import hashlib
import ECDSA

OP_0 = 0
OP_1 = 81
OP_16 = 96
OP_DUP = 118
OP_ADD = 147
OP_HASH160 = 169
OP_HASH256 = 170
OP_CHECKSIG = 172
OP_CHECKSIGVERIFY = 173
OP_CHECKMULTISIG = 174
OP_CHECKMULTISIGVERIFY = 175
OP_PUSHDATA1 = 76
OP_PUSHDATA2 = 77
OP_EQUAL = 135
OP_EQUALVERIFY = 136

def op_dup(stack):
    if len(stack) < 1: return False
    stack.append(stack[-1])
    return True

def op_hash256(stack):
    if len(stack) < 1: return False
    b = hashlib.sha256(stack.pop()).digest()
    b = hashlib.sha256(b).digest()
    stack.append(b)
    return True

def op_hash160(stack):
    if len(stack) < 1: return False
    b = hashlib.sha256(stack.pop()).digest()
    b = hashlib.new('ripemd160', b).digest()
    stack.append(b)
    return True

def op_checksig(stack, signee):
    if len(stack) < 2: return False
    pk = ECDSA.PubkeyFromSEC(stack.pop())
    sig = ECDSA.SigFromDER(stack.pop()[:-1])
    if ECDSA.verify(signee, sig, pk):
        stack.append(b'\x01')
    else:
        stack.append(b'')
    return True

def op_checkmultisig(stack, signee):
    if len(stack) < 1: return False
    n = int.from_bytes(stack.pop(), 'little')

    if len(stack) <= n: return False
    pks,sigs = [],[]

    for _ in range(n):
        pks.append(ECDSA.PubkeyFromSEC(stack.pop()))

    m = int.from_bytes(stack.pop(), 'little')
    if len(stack) <= m: return False
    for _ in range(m):
        sigs.append(ECDSA.SigFromDER(stack.pop()[:-1]))

    stack.pop()

    for sig in sigs:
        if len(pks)==0: return False
        while pks:
            if ECDSA.verify(signee, sig, pks.pop(0)):
                break

    return True

def op_equalverify(stack):
    if len(stack) < 2: return False
    return stack.pop() == stack.pop()

OP_FUNCTIONS = {
    OP_DUP: op_dup,
    OP_HASH160: op_hash160,
    OP_HASH256: op_hash256,
    OP_CHECKSIG: op_checksig,
    OP_CHECKMULTISIG: op_checkmultisig,
    OP_EQUALVERIFY: op_equalverify,
}

OP_2ARG = (
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY
)
