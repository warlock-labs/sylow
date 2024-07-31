from sagelib.multiplication import *
from sagelib.division import *
from sagelib.frobenius import print_quadratic_non_residues, print_frobenius_coeffs
from sagelib.g1 import generate_reference_json

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