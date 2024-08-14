import logging
import sys

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
Fp = GF(p)

R.<u> = PolynomialRing(Fp)
Fp2.<u> = Fp.extension(u^2+1)

S.<v> = PolynomialRing(Fp2)
Fp6.<v> = Fp2.extension(v^3 - (9+u))


# T.<w> = PolynomialRing(Fp6)
# Fp12.<w> = Fp6.extension(w^2-v)
# Fp2.<u> = GF(p^2, modulus=x^2+1)

E1 = EllipticCurve(Fp,[0,3])
E2 = EllipticCurve(Fp2, [0, 3/(9+u)])
r = int(E1.order())

epsExp0 = Fp2([21575463638280843010398324269430826099269044274347216827212613867836435027261,
               10307601595873709700152284273816112264069230130616436755625194854815875713954])

# Define eps^((p-1)/2)
epsExp1 = Fp2([2821565182194536844548159561693502659359617185244120367078079554186484126554,
               3505843767911556378687030309984248845540243509899259641013678093033130930403])
               
def psi(P):
    """
    Apply the endomorphism to a point P in G2.
    """
    if P.is_zero():
        return P

    x, y = P.xy()

    # Frobenius
    x_frob = x^p#x.frobenius()
    y_frob = y^p#y.frobenius()

    # x coordinate endomorphism
    x_endo = epsExp0 * x_frob

    # y coordinate endomorphism
    y_endo = epsExp1 * y_frob

    # Return the new point
    return P.curve()(x_endo, y_endo)
    
logging.info(f"Running with modulus: {p}")
