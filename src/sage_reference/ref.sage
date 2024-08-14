from sagelib.multiplication import *
from sagelib.division import *
from sagelib.frobenius import print_quadratic_non_residues, print_frobenius_coeffs
from sagelib.g1 import *
from sagelib.g2 import *
from sagelib.utils import *
def generate_reference_json():
    import json
    num_points = 1000
    points = {
        "g1": {'a': [], 'b': [], 'r': [], 'add': [], 'dbl': [], 'mul': [], 'svdw': []},
        "g2": {'a': [], 'b': [], 'r': [], 'add': [], 'dbl': [], 'mul': [], 'svdw': [], 'invalid': [], 'psi': []},
    }
    for func, curve, label in zip([generate_g1_data, generate_g2_data], [E1, E2], ['g1', 'g2']):
        A, B, R, Add, Dbl, Mul = func(num_points)
        svdw = generic_svdw(curve)
        for _ in range(num_points):
            u = Fp.random_element()
            if u not in svdw.undefs:
                x, y = svdw.map_to_point(u)
                assert curve(x,y), f"point ({x},{y}) is not on curve {curve} for u={u}"
                points[label]['svdw'].append({
                    "i": str(u),
                    **point_to_json(curve(x,y))
                })
        for a, b, r, add, dbl, mul in zip(A, B, R, Add, Dbl, Mul):
            points[label]['a'].append(point_to_json(a))
            points[label]['b'].append(point_to_json(b))
            points[label]['r'].append(str(int(r)))
            points[label]['add'].append(point_to_json(add))
            points[label]['dbl'].append(point_to_json(dbl))
            points[label]['mul'].append(point_to_json(mul))
            if label=='g2':
                points[label]['psi'].append(point_to_json(psi(a)))
    for _ in range(num_points):
        points["g2"]['invalid'].append(point_to_json(generate_non_r_torsion_point()))

    with open('bn254_reference.json', 'w') as f:
    	f.write(json.dumps(points,indent=2))

if __name__ == "__main__":
    logging.info("*" * 20 + "Mul tests" + "*" * 20)
    for instance in [
        FieldMultiplicationTest(),
        QuadraticFieldMultiplicationTest(),
        SexticFieldMultiplicationTest(),
    ]:
        for method_name in dir(instance):
            if method_name.startswith("test_"):
                getattr(instance, method_name)()
    logging.info("All multiplication tests passed successfully!")

    logging.info("*" * 20 + "Div tests" + "*" * 20)
    for instance in [
        FieldDivisionTest(),
        QuadraticFieldDivisionTest(),
        SexticFieldDivisionTest(),
    ]:
        for method_name in dir(instance):
            if method_name.startswith("test_"):
                getattr(instance, method_name)()
    logging.info("All division tests passed successfully!")

    print_quadratic_non_residues()
    print_frobenius_coeffs()
    generate_reference_json()