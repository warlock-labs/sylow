from sagelib.facts import *
from sagelib.svdw import *

# this is the generator of the r-torsion
G2 = E2(Fp2([10857046999023057135944570762232829481370756359578518086990519993285655852781,
11559732032986387107991004021392285783925812861821192530917403151452391805634]),
      Fp2([8495653923123431417604973247489272438418190587263600148770280649306958101930, 4082367875863433681332203403145435568316851327593401208105741076214120093531]))


def random_g2(n): #returns random values in the r-torsion
    retval  = []
    for _ in range(n):
        rando = G2*randint(1, order_r-1)
        assert(is_in_subgroup(rando))
        retval.append(rando)
    return retval

def generate_g2_data(n=1000):
    S = random_g2(n)
    T = random_g2(n)
    R = [Fp.random_element() for _ in range(n)]
    Addition = [s + t for s,t in zip(S, T)]
    Doubling = [2*s for s in S]
    Multiplication = [r*s for r, s in zip(R,S)]
    return S, T, R, Addition, Doubling, Multiplication


def generate_non_r_torsion_point():
    P = E2.random_point() # E2(2,sqrt(2**3+b))
    # We want P to be of order 10069
    P = 5864401 * 1875725156269 * 197620364512881247228717050342013327560683201906968909 * E1.order() * P
    return P

epsExp0 = Fp2([21575463638280843010398324269430826099269044274347216827212613867836435027261,
               10307601595873709700152284273816112264069230130616436755625194854815875713954])

# Define eps^((p-1)/2)
epsExp1 = Fp2([2821565182194536844548159561693502659359617185244120367078079554186484126554,
               3505843767911556378687030309984248845540243509899259641013678093033130930403])
               
def endomorphism(P):
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
    
def is_in_subgroup(Q):
    """
    Check if a point is in the subgroup of order r.
    """
    z = 4965661367192848881
    lhs = endomorphism(Q)
    rhs = 6*z*z*Q
    return (lhs-rhs).is_zero()