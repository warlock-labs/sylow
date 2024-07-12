## Barreto-Naehrig (BN) Curves

### Definition and Properties

Barreto-Naehrig (BN) curves are a family of pairing-friendly elliptic curves defined over a prime field $\mathbb{F}_p$. They have the following key properties:

1. Prime order: The order of the curve is a prime number $n$.
2. Embedding degree: $k = 12$
3. CM discriminant: $D = 3$
4. Equation form: $E: y^2 = x^3 + b$, where $b \neq 0$

BN curves are particularly significant because:
- They support curves of prime order, which is crucial for certain applications and efficient implementations.
- They have an embedding degree of 12, which provides a good balance between security and efficiency for pairing-based cryptography.

### Parameterization

BN curves are parameterized by a single integer $x$. The key parameters of the curve are defined as polynomials in $x$:

1. Trace of Frobenius: $t(x) = 6x^2 + 1$
2. Prime field order: $p(x) = 36x^4 - 36x^3 + 24x^2 - 6x + 1$
3. Curve order: $n(x) = 36x^4 - 36x^3 + 18x^2 - 6x + 1$

For cryptographic use, $x$ is chosen such that both $p(x)$ and $n(x)$ are prime numbers of the desired bit-length.

### Embedding Degree

The embedding degree $k$ of a curve $E$ over $\mathbb{F}_p$ with respect to a subgroup of prime order $r$ is the smallest positive integer $k$ such that $r | (p^k - 1)$.

For BN curves:
- The embedding degree is always $k = 12$.
- This means that the smallest extension field $\mathbb{F}_{p^k}$ that contains the $r$-th roots of unity is $\mathbb{F}_{p^{12}}$.

The embedding degree is crucial for pairing-based cryptography because:
1. It determines the field in which pairing computations take place.
2. It affects the security level of the pairing-based system.
3. It influences the efficiency of pairing computations.

For BN curves, $k = 12$ provides a good balance:
- It's large enough to provide sufficient security against index calculus attacks on the discrete logarithm problem in the extension field.
- It's small enough to allow for efficient implementation of field arithmetic in $\mathbb{F}_{p^{12}}$.

### Construction and Usage

To construct a BN curve for cryptographic use:

1. Choose an integer $x$ with low Hamming weight to optimize certain operations.
2. Compute $p(x)$ and $n(x)$. If both are prime, proceed; otherwise, choose a different $x$.
3. The curve equation is $E: y^2 = x^3 + b$, where $b$ is typically chosen to be a small integer (often 2 or 3).
4. The curve is defined over $\mathbb{F}_p$, where $p = p(x)$.
5. The order of the curve is $n = n(x)$.

