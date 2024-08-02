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


def point_to_json(P):
    if P.is_zero():
        return {"x": "0", "y": "0", "z": "0"}
    x, y, z = list(P)
    if P.curve() == E1:
        return {"x": str(x), "y": str(y), "z": str(z)}
    else:  # E2
        return {
            "x": {"c0": str(x[0]), "c1": str(x[1])},
            "y": {"c0": str(y[0]), "c1": str(y[1])},
            "z": {"c0": str(z[0]), "c1": str(z[1])}
        }

def generate_reference_json():
    import json
    num_points = 1000
    points = {
        "g1": {'a': [], 'b': [], 'r': [], 'add': [], 'dbl': [], 'mul': []},
        "svdw": []
    }
    A, B, R, Add, Dbl, Mul = generate_g1_data(num_points)
    svdw = generic_svdw(E1)
    for _ in range(num_points):
        u = Fp.random_element()
        if u not in svdw.undefs:
            x, y = svdw.map_to_point(u)
            assert E1(x,y), f"point ({x},{y}) is not on curve for u={u}"
            points['svdw'].append({
                "i": str(u),
                **point_to_json(E1(x,y))
            })
    for a, b, r, add, dbl, mul in zip(A, B, R, Add, Dbl, Mul):
        points["g1"]['a'].append(point_to_json(a))
        points["g1"]['b'].append(point_to_json(b))
        points["g1"]['r'].append(str(int(r)))
        points["g1"]['add'].append(point_to_json(add))
        points["g1"]['dbl'].append(point_to_json(dbl))
        points["g1"]['mul'].append(point_to_json(mul))

    with open('bn254_reference.json', 'w') as f:
    	f.write(json.dumps(points,indent=2))