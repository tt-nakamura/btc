class EC_p:
    @classmethod
    def init(cls, modulus, a, b, gen_x, gen_y, order):
        cls.modulus = modulus
        cls.a = a
        cls.b = b
        cls.order = order
        cls.generator = cls(gen_x, gen_y)

    def __init__(self,x,y):
        self.x = x
        self.y = y

    def __eq__(self, P):
        if self.x is None: return P.x is None
        return self.x == P.x and self.y == P.y

    def __neg__(self):
        if not self.y: return self
        return self.__class__(self.x, self.modulus - self.y)

    def __add__(self, P):
        if self.x is None: return P
        if P.x    is None: return self
        if self.x != P.x:
            s = InvMod(P.x - self.x, self.modulus)
            s = s*(P.y - self.y) % self.modulus
        elif self.y == P.y and self.y:
            s = self.x * self.x % self.modulus
            s = (3*s + self.a) % self.modulus
            s = s * InvMod(2*self.y, self.modulus) % self.modulus
        else:
            return self.__class__(None, None)

        x = (s*s - self.x - P.x) % self.modulus
        y = (s*(self.x - x) - self.y) % self.modulus
        return self.__class__(x,y)

    def __rmul__(self, n):
        if n==0: return self.__class__(None, None)
        n %= self.order
        m = (1<<(n.bit_length() - 1))>>1
        P = self
        while m:
            P += P
            if n&m: P += self
            m >>= 1
        return P

    @classmethod
    def ysquare(cls, x):
        y = (x*x % cls.modulus + cls.a)*x
        return (y + cls.b) % cls.modulus


def InvMod(a,p):
    s,u = 1,0
    while p:# euclid
        q,r = divmod(a,p)
        a,p = p,r
        s,u = u,s-q*u
    return s
