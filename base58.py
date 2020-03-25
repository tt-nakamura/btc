BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def Base58FromInt(n):
    s = '';
    while n:
        n,r = divmod(n, 58)
        s = BASE58_ALPHABET[r] + s
    return s

def IntFromBase58(s):
    i = 0
    for c in s:
        i *= 58
        i += BASE58_ALPHABET.index(c)

    return i
