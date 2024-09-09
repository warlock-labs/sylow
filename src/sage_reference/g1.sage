from sagelib.facts import *
from sagelib.svdw import *
def random_g1(n):
    return [E1.random_point() for _ in range(n)]

def generate_g1_data(n=1000):
    S = random_g1(n)
    T = random_g1(n)
    R = [Fp.random_element() for _ in range(n)]
    Addition = [s + t for s,t in zip(S, T)]
    Doubling = [2*s for s in S]
    Multiplication = [r*s for r, s in zip(R,S)]
    return S, T, R, Addition, Doubling, Multiplication


