p =21888242871839275222246405745257275088696311157297823662689037894645226208583
Fp = GF(p)

Fp2.<u> = GF(p^2, modulus=x^2+1)
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

def u256_to_u64_list_hex(u256_value):
    if u256_value < 0 or u256_value >= 2**256:
        raise ValueError("Input must be a 256-bit non-negative integer")

    # Convert to 256-bit binary string, pad with zeros if necessary
    binary = format(u256_value, '0256b')
    
    # Split into 4 64-bit chunks (little-endian order)
    chunks = [binary[i:i+64] for i in range(0, 256, 64)]
    chunks.reverse()  # Reverse for little-endian

    # Convert each chunk to an integer and then to hex
    hex_list = [hex(int(chunk, 2)) for chunk in chunks]
    
    return hex_list

def u64_list_to_u256(u64_list):
    if len(u64_list) != 4:
        raise ValueError("Input list must contain exactly 4 u64 integers")
    
    # Convert each u64 to 64-bit binary string, ensuring 64 bits
    binary_strings = [format(x & ((1 << 64) - 1), '064b') for x in u64_list]

    # Reverse the list for little-endian
    binary_strings.reverse()

    # Concatenate all binary strings
    full_binary = ''.join(binary_strings)

    # Convert binary string to integer
    return int(full_binary, 2)


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

a = Fp2(0x0000000000000001000000000000000200000000000000030000000000000004 + u*0x0000000000000001000000000000000100000000000000010000000000000001)
b = Fp2(0x0000000000000001000000000000000100000000000000010000000000000001 + u*0x0000000000000004000000000000000300000000000000020000000000000001)
c = a/b
c0, c1 = [u256_to_u64_list_hex(int(i)) for i in list(c)]
#print(c0)
#print(c1)
# print(u64_list_to_u256([0x2221d7e243f5a6b7, 0xf2dbb3e54415ac43, 0xc1c16c86d80ba3fe, 0x1ed70a64be2c4cf4]))
# print(list(c)[0])

nonres = Fp2(0x0000000000000000000000000000000000000000000000000000000000000009+u
*0x0000000000000000000000000000000000000000000000000000000000000001)
e = (2*p^5-2)/3
d = nonres^(e)
print(d)
for i in list(d):
    h = u256_to_u64_list_hex(int(i))
    print("Fp::new(U256::from_words([\n")
    for j in h:
        print(f"\t{j},\n")
    print("]))")

