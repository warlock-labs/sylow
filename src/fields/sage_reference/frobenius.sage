from sagelib.facts import *
from sagelib.utils import recursive_flatten, u256_to_u64_list_hex

fp_non_residue = -Fp(1)
fp2_non_residue = Fp2(9 + 1 * u)
fp6_non_residue = Fp6(u)

fp_frob_coeffs = Fp(0)
fp2_frob_coeffs = [fp_non_residue ^ ((p ^ i - 1) / 2) for i in range(2)]
fp6_frob_coeffs = [
    [fp2_non_residue ^ ((p ^ i - 1) / 3) for i in range(6)],
    [fp2_non_residue ^ ((2 * p ^ i - 2) / 3) for i in range(6)],
]
fp12_frob_coeffs = [fp2_non_residue ^ ((p ^ i - 1) / 6) for i in range(12)]

def print_quadratic_non_residues():
    l = [fp_non_residue, fp2_non_residue, fp6_non_residue]
    logging.info("*" * 20 + "Non-residues" + "*" * 20)
    for item in l:
        ret = []
        for h in recursive_flatten(item):
            ret.append(u256_to_u64_list_hex(int(h)))
        logging.info(ret)


def print_frobenius_coeffs():
    l = [fp_frob_coeffs, fp2_frob_coeffs, fp6_frob_coeffs, fp12_frob_coeffs]
    logging.info("*" * 20 + "Frobenius coeffs" + "*" * 20)
    for item in l:
        ret = []
        for h in recursive_flatten(item):
            ret.append(str(u256_to_u64_list_hex(int(h))))
        logging.info("\n".join(ret))
