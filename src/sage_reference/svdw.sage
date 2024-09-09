ZZR = PolynomialRing(ZZ, name='XX')

CMOV = lambda x, y, b: int(not bool(b))*x + int(bool(b))*y

def sgn0(x):
    """
    Returns 1 if x is 'negative' (little-endian sense), else 0.
    """
    degree = x.parent().degree()
    if degree == 1:
        # not a field extension
        xi_values = (ZZ(x),)
    else:
        # field extension
        xi_values = ZZR(x)  # extract vector repr of field element (faster than x._vector_())
    sign = 0
    zero = 1
    # compute the sign in constant time
    for i in range(0, degree):
        zz_xi = xi_values[i]
        # sign of this digit
        sign_i = zz_xi % 2
        zero_i = zz_xi == 0
        # update sign and zero
        sign = sign | (zero & sign_i)
        zero = zero & zero_i
    return sign

def find_z_svdw(F, A, B, init_ctr=1):
    g = lambda x: F(x)^3 + F(A) * F(x) + F(B)
    h = lambda Z: -(F(3) * Z^2 + F(4) * A) / (F(4) * g(Z))
    ctr = init_ctr
    while True:
        for Z_cand in (F(ctr), F(-ctr)):
            #   g(Z) != 0 in F.
            if g(Z_cand) == F(0):
                continue
            #   -(3 * Z^2 + 4 * A) / (4 * g(Z)) != 0 in F.
            if h(Z_cand) == F(0):
                continue
            #   -(3 * Z^2 + 4 * A) / (4 * g(Z)) is square in F.
            if not is_square(h(Z_cand)):
                continue
            #   At least one of g(Z) and g(-Z / 2) is square in F.
            if is_square(g(Z_cand)) or is_square(g(-Z_cand / F(2))):
                return Z_cand
        ctr += 1
        
# based on method at https://eprint.iacr.org/2019/403.pdf, 
# based on RFC9830's draft-irtf-cfrg-hash-to-curve impl
class generic_svdw:
    sgn0 = staticmethod(sgn0)
    sqrt = staticmethod(sqrt)
    
    def inv0(self, x):
        if self.F(x) == 0:
            return self.F(0)
        return self.F(1) / self.F(x)
    
    def is_square(self, x):
        return self.F(x).is_square()
    
    def __init__(self, EC):
        self.F = EC.base_field()
        self.A = self.F(EC.a4())
        self.B = self.F(EC.a6())
        self.Z = find_z_svdw(self.F, self.A, self.B)
        self.g = lambda x: self.F(x)**3 + self.A * self.F(x) + self.B
        self.E = EC
        # constants for straight-line impl
        mgZ = -self.g(self.Z)
        self.c1 = self.g(self.Z)
        self.c2 = self.F(-self.Z / self.F(2))
        self.c3 = (mgZ * (3 * self.Z^2 + 4 * self.A)).sqrt()
        if self.sgn0(self.c3) == 1:
            self.c3 = -self.c3
        assert self.sgn0(self.c3) == 0
        self.c4 = self.F(4) * mgZ / (3 * self.Z^2 + 4 * self.A)

        # values at which the map is undefined
        self.undefs = []
        for zz in (self.F(1)/mgZ, self.F(-1)/mgZ):
            if zz.is_square():
                sqrt_zz = zz.sqrt()
                self.undefs += [sqrt_zz, -sqrt_zz]

    def map_to_point(self, u):
        # straightline implementation
        u = self.F(u)
        inv0 = self.inv0
        is_square = self.is_square
        sgn0 = self.sgn0
        sqrt = self.sqrt
        c1 = self.c1
        c2 = self.c2
        c3 = self.c3
        c4 = self.c4
        A = self.A
        B = self.B
        Z = self.Z

        tv1 = u^2
        tv1 = tv1 * c1
        tv2 = 1 + tv1
        tv1 = 1 - tv1
        tv3 = tv1 * tv2
        tv3 = inv0(tv3)
        tv4 = u * tv1
        tv4 = tv4 * tv3
        tv4 = tv4 * c3
        x1 = c2 - tv4
        gx1 = x1^2
        gx1 = gx1 + A
        gx1 = gx1 * x1
        gx1 = gx1 + B
        e1 = is_square(gx1)
        x2 = c2 + tv4
        gx2 = x2^2
        gx2 = gx2 + A
        gx2 = gx2 * x2
        gx2 = gx2 + B
        e2 = is_square(gx2) and not e1     # Avoid short-circuit logic ops
        x3 = tv2^2
        x3 = x3 * tv3
        x3 = x3^2
        x3 = x3 * c4
        x3 = x3 + Z
        x = CMOV(x3, x1, e1)      # x = x1 if gx1 is square, else x = x3
        x = CMOV(x, x2, e2)       # x = x2 if gx2 is square and gx1 is not
        gx = x^2
        gx = gx + A
        gx = gx * x
        gx = gx + B
        y = sqrt(gx)
        e3 = sgn0(u) == sgn0(y)
        y = CMOV(-y, y, e3)       # Select correct sign of y
        return (x, y)