from sagelib.utils import *
from operator import truediv


class FieldDivision(metaclass=FieldTestMetaclass):
    def __init__(self):
        self.D = 1
        self.operation = truediv


class QuadraticFieldDivision(metaclass=FieldTestMetaclass):
    def __init__(self):
        self.D = 2
        self.operation = truediv


class SexticFieldDivision(metaclass=FieldTestMetaclass):
    def __init__(self):
        self.D = 6
        self.operation = truediv


# class DodecticFieldDivision(metaclass=FieldTestMetaclass, D=2):
#     pass


class FieldDivisionTest(FieldDivision):
    Fp_test_values = [
        ([1, 2, 3, 4], [1, 0, 0, 0]),
    ]


class QuadraticFieldDivisionTest(QuadraticFieldDivision):
    Fp2_test_values = [
        ([[4, 3, 2, 1], [1, 1, 1, 1]], [[1, 1, 1, 1], [1, 2, 3, 4]]),
    ]


#
class SexticFieldDivisionTest(SexticFieldDivision):
    Fp6_test_values = [
        (
            [
                [[1, 0, 0, 0], [0, 2, 0, 0]],
                [[0, 0, 3, 0], [0, 0, 0, 4]],
                [[5, 0, 0, 0], [0, 6, 0, 0]],
            ],
            [
                [[0, 6, 0, 0], [5, 0, 0, 0]],
                [[0, 0, 0, 4], [0, 0, 3, 0]],
                [[0, 2, 0, 0], [1, 0, 0, 0]],
            ],
        )
    ]
