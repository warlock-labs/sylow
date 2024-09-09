import logging
import sys

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
order_r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
c2 = 21888242871839275222246405745257275088844257914179612981679871602714643921549

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

assert E2.order() == c2*order_r


logging.info(f"Running with modulus: {p}")
