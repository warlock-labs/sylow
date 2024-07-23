from sage.all import *
from operator import mul
from collections.abc import Iterable


def assertTrue(condition, message=""):
    assert condition, message


def assertEqual(first, second, message=""):
    assert first == second, message
is_iterable = lambda obj: isinstance(obj, Iterable)

def recursive_flatten(item, depth=0):
    if is_iterable(item):
        return [element for sublist in item for element in recursive_flatten(sublist, depth + 1)]
    else:
        return [item]
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
Fp = GF(p)

R.<u> = PolynomialRing(Fp)
Fp2.<u> = Fp.extension(u^2+1)

S.<v> = PolynomialRing(Fp2)
Fp6.<v> = Fp2.extension(v^3 - (9+u))


# T.<w> = PolynomialRing(Fp6)
# Fp12.<w> = Fp6.extension(w^2-v)
# Fp2.<u> = GF(p^2, modulus=x^2+1)
def u256_to_u64_list_hex(u256_value):
    if u256_value < 0 or u256_value >= 2**256:
        raise ValueError("Input must be a 256-bit non-negative integer")

    # Convert to 256-bit binary string, pad with zeros if necessary
    binary = format(u256_value, "0256b")

    # Split into 4 64-bit chunks (little-endian order)
    chunks = [binary[i : i + 64] for i in range(0, 256, 64)]
    chunks.reverse()  # Reverse for little-endian

    # Convert each chunk to an integer and then to hex
    hex_list = [hex(int(chunk, 2)) for chunk in chunks]

    return hex_list


def u64_list_to_u256(u64_list):
    if len(u64_list) != 4:
        raise ValueError("Input list must contain exactly 4 u64 integers")

    # Convert each u64 to 64-bit binary string, ensuring 64 bits
    binary_strings = [format(x & ((1 << 64) - 1), "064b") for x in u64_list]

    # Reverse the list for little-endian
    binary_strings.reverse()

    # Concatenate all binary strings
    full_binary = "".join(binary_strings)

    # Convert binary string to integer
    return int(full_binary, 2)


def convert_to_field(value, field):
    if field == Fp:
        return Fp(u64_list_to_u256(value))
    elif field == Fp2:
        return Fp2([convert_to_field(v, Fp) for v in value])
    elif field == Fp6:
        return Fp6([convert_to_field(v, Fp2) for v in value])
    elif field == Fp12:
        return Fp12([convert_to_field(v, Fp6) for v in value])
    else:
        raise ValueError(f"Unsupported field: {field}")


class FieldTestMetaclass(type):
    def __new__(cls, name, bases, attrs, operation=mul, **kwargs):
        D = kwargs.get('D', 2)  # Get D from kwargs, default to 5 if not provided
        fields = [Fp, Fp2, Fp6]
        field_names = ["Fp", "Fp2", "Fp6"]

        for field, field_name in zip(fields, field_names):

            def create_test_method(f, fn):
                def test_method(self):
                    test_values = getattr(self, f"{fn}_test_values", [])
                    if not test_values:
                        # test_values = [(f.random_element(), f.random_element()) for _ in range(3)]
                        return
                    # print(f"Running {field_name}...")
                    for value in test_values:
                        a, b = value
                        a = convert_to_field(a, f)
                        b = convert_to_field(b, f)
                        for j in [a, b]:
                            if is_iterable(j):
                                flattened = recursive_flatten(j)
                                # max_depth = max(isinstance(x, list) for x in j) + 1 if isinstance(j, list) else 1
                            if isinstance(j, Iterable):
                                assertEqual(
                                    len(flattened),
                                    self.D,
                                    f"Input test {j} is not correct length (D={self.D})",
                                )
                        result = operation(a, b)
                        assertTrue(
                            result in f, f"{fn} multiplication result not in field"
                        )
                        assertEqual(
                            result, a * b, f"{fn} multiplication not consistent"
                        )

                        # Debug print with limited number of elements
                        print(f"Debug {fn}: a = {self.limited_repr(a, self.D)}")
                        print(f"Debug {fn}: b = {self.limited_repr(b, self.D)}")
                        print(
                            f"Debug {fn}: result = {self.limited_repr(result, self.D)}"
                        )
                        print("-" * 50)

                # print(f"{field_name} passed!")
                return test_method

            attrs[f"test_{field_name}_multiplication"] = create_test_method(
                field, field_name
            )

        # Add the limited_repr method to the class
        def limited_repr(self, element, limit):
            try:
                coeffs = list(element)
                return (
                    "\n\t"
                    + " ".join(self.limited_repr(coeff, 1) for coeff in coeffs)
                    + "\n"
                )

            except TypeError:
                # If list(element) raises TypeError, treat it as a single value
                try:
                    # Try to convert to integer and use u256_to_u64_list_hex
                    int_value = int(element)
                    return str(u256_to_u64_list_hex(int_value))
                except (ValueError, TypeError):
                    # If conversion fails, fall back to default representation
                    return repr(element)

        attrs["limited_repr"] = limited_repr
        attrs["D"] = D

        return super().__new__(cls, name, bases, attrs)


class FieldMultiplication(metaclass=FieldTestMetaclass):
    def __init__(self):
        self.D = 1

class QuadraticFieldMultiplication(metaclass=FieldTestMetaclass):
    def __init__(self):
        self.D = 2
class SexticFieldMultiplication(metaclass=FieldTestMetaclass):
    def __init__(self):
        self.D = 6

# class DodecticFieldMultiplication(metaclass=FieldTestMetaclass, D=2):
#     pass


class FieldMultiplicationTest(FieldMultiplication):
    Fp_test_values = [
        ([2, 0, 0, 0], [3, 0, 0, 0]),
        ([0xFFFFFFFFFFFFFFFF, 0, 0, 0], [2, 0, 0, 0]),
        (
            [
                0x1E104C0B6C3E7EA3,
                0x4BC0B5488C38E546,
                0x5C28222B40C0AC2E,
                0x18322739709D8814,
            ],
            [2, 0, 0, 0],
        ),
        (
            [
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0x3064497359141831,
            ],
            [
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0x3064497359141831,
            ],
        ),
    ]


class QuadraticFieldMultiplicationTest(QuadraticFieldMultiplication):
    Fp2_test_values = [
        ([[4, 3, 2, 1], [1, 1, 1, 1]], [[1, 1, 1, 1], [1, 2, 3, 4]]),
        ([[0xFFFFFFFFFFFFFFFF, 0, 0, 0],
          [0xFFFFFFFFFFFFFFFF, 0, 0, 0]],[[0xFFFFFFFFFFFFFFFF, 0, 0, 0], [2, 0, 0, 0]])
    ]


#
class SexticFieldMultiplicationTest(SexticFieldMultiplication):
    Fp6_test_values = [
        ([
             [
                [1, 0, 0, 0],
                [0, 2, 0, 0]
             ],
             [
                [0, 0, 3, 0],
                [0, 0, 0, 4]
             ],
             [
                [5, 0, 0, 0],
                [0, 6, 0, 0]
             ]
        ],
        [
            [
                [0, 6, 0, 0],
                [5, 0, 0, 0]
            ],
            [
                [0, 0, 0, 4],
                [0, 0, 3, 0]
            ],
            [
                [0, 2, 0, 0],
                [1, 0, 0, 0]
            ]
        ]),
    ]

# Fp12_test_values = [
#     (Fp12.random_element(), Fp12.random_element()),
# ]

# Run all the tests

for instance in [
    FieldMultiplicationTest(),
    QuadraticFieldMultiplicationTest(),
    SexticFieldMultiplicationTest()
]:
    for method_name in dir(instance):
        if method_name.startswith("test_"):
            getattr(instance, method_name)()

print("All tests passed successfully!")


def determine_uint_size(n):
    bit_length = n.nbits()

    if bit_length <= 8:
        return "U8"
    elif bit_length <= 16:
        return "U16"
    elif bit_length <= 32:
        return "U32"
    elif bit_length <= 64:
        return "U64"
    elif bit_length <= 128:
        return "U128"
    elif bit_length <= 256:
        return "U256"
    elif bit_length <= 512:
        return "U512"
    elif bit_length <= 1024:
        return "U1024"
    elif bit_length <= 2048:
        return "U2048"
    elif bit_length <= 4096:
        return "U4096"
    else:
        return f"Needs more than 2048 bits (actual: {bit_length} bits)"


# u64_list = [
#     0x3C208C16D87CFD47,
#     0x97816A916871CA8D,
#     0xB85045B68181585D,
#     0x30644E72E131A029
# ]

# u256_value = u64_list_to_u256(u64_list)

# print(f"u256 value: {u256_value}")
# print(f"In hexadecimal: {hex(u256_value)}")

# from_words = lambda arr: hex(u64_list_to_u256(arr))
# print(from_words([1,1,1,1]))
# a = Fp2(from_words([1,1,1,1]), from_words([1,1,1,1]))
# b = Fp2(from_words([1,1,1,1]), from_words([1,1,1,1]))
# print(from_words([4,3,2,1]))

a = Fp2(
    0x0000000000000001000000000000000200000000000000030000000000000004
    + u * 0x0000000000000001000000000000000100000000000000010000000000000001
)
b = Fp2(
    0x0000000000000001000000000000000100000000000000010000000000000001
    + u * 0x0000000000000004000000000000000300000000000000020000000000000001
)
c = a / b
c0, c1 = [u256_to_u64_list_hex(int(i)) for i in list(c)]
# print(c0)
# print(c1)
# print(u64_list_to_u256([0x2221d7e243f5a6b7, 0xf2dbb3e54415ac43, 0xc1c16c86d80ba3fe, 0x1ed70a64be2c4cf4]))
# print(list(c)[0])

nonres = Fp2(
    0x0000000000000000000000000000000000000000000000000000000000000009
    + u * 0x0000000000000000000000000000000000000000000000000000000000000001
)
e = (2 * p ^ 5 - 2) / 3
d = nonres ^ (e)
print(d)
for i in list(d):
    h = u256_to_u64_list_hex(int(i))
    print("Fp::new(U256::from_words([\n")
    for j in h:
        print(f"\t{j},\n")
    print("]))")
