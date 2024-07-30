from sagelib.facts import *
from operator import mul, truediv
from collections.abc import Iterable

symbols = {mul: "*", truediv: "/"}


def assertTrue(condition, message=""):
    assert condition, message


def assertEqual(first, second, message=""):
    assert first == second, message


is_iterable = lambda obj: isinstance(obj, Iterable)


def recursive_flatten(item, depth=0):
    if is_iterable(item):
        return [
            element
            for sublist in item
            for element in recursive_flatten(sublist, depth + 1)
        ]
    else:
        return [item]


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
    def __new__(cls, name, bases, attrs, **kwargs):
        D = kwargs.get("D", 2)  # Get D from kwargs, default to 5 if not provided
        operation = kwargs.get("operator", mul)
        fields = [Fp, Fp2, Fp6]
        field_names = ["Fp", "Fp2", "Fp6"]

        for field, field_name in zip(fields, field_names):

            def create_test_method(f, fn):
                def test_method(self):
                    test_values = getattr(self, f"{fn}_test_values", [])
                    if not test_values:
                        return
                    for value in test_values:
                        a, b = value
                        a = convert_to_field(a, f)
                        b = convert_to_field(b, f)
                        for j in [a, b]:
                            if is_iterable(j):
                                flattened = recursive_flatten(j)
                            if isinstance(j, Iterable):
                                assertEqual(
                                    len(flattened),
                                    self.D,
                                    f"Input test {j} is not correct length (D={self.D})",
                                )
                        result = self.operation(a, b)
                        assertTrue(
                            result in f, f"{fn} multiplication result not in field"
                        )
                        assertEqual(
                            result,
                            self.operation(a, b),
                            f"{fn} multiplication not consistent",
                        )

                        # Debug print with limited number of elements
                        logging.debug(f"{fn}: a = {self.limited_repr(a, self.D)}")
                        logging.debug(f"{fn}: b = {self.limited_repr(b, self.D)}")
                        logging.debug(
                            f"{fn}: a{symbols[self.operation]}b = {self.limited_repr(result, self.D)}"
                        )

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
