from sagelib.utils import *
from operator import mul
class FieldMultiplication(metaclass=FieldTestMetaclass):
    def __init__(self):
        self.D = 1
        self.operation = mul

class QuadraticFieldMultiplication(metaclass=FieldTestMetaclass):
    def __init__(self):
        self.D = 2
        self.operation = mul
class SexticFieldMultiplication(metaclass=FieldTestMetaclass):
    def __init__(self):
        self.D = 6
        self.operation = mul

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
        ([
             [
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0]
             ],
             [
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0]
             ],
             [
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0]
             ]
         ],
         [
             [
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0]
             ],
             [
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0]
             ],
             [
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                 [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0]
             ]
         ])
    ]
