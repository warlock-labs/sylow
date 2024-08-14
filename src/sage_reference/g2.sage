from sagelib.facts import *
from sagelib.svdw import *
def random_g2(n):
    return [E2.random_point() for _ in range(n)]

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