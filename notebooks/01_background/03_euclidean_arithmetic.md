## Number Theory

### Prime Numbers and Divisibility

A prime number is a natural number greater than 1 that is only divisible by 1 and itself. The fundamental theorem of arithmetic states that every integer greater than 1 can be uniquely represented as a product of prime powers.

For integers $a$ and $b$, we say $a$ divides $b$ (denoted $a \mid b$) if there exists an integer $k$ such that $b = ak$. If $a \mid b$ and $a \mid c$, then $a \mid (bx + cy)$ for any integers $x$ and $y$.

### Greatest Common Divisor (GCD)

The greatest common divisor of two integers $a$ and $b$, denoted $\gcd(a,b)$, is the largest positive integer that divides both $a$ and $b$. Key properties include:

1. $\gcd(a,b) = \gcd(|a|,|b|)$
2. $\gcd(a,b) = \gcd(b, a \bmod b)$ (basis for the Euclidean algorithm)
3. There exist integers $x$ and $y$ such that $\gcd(a,b) = ax + by$ (Bézout's identity)

### Integral Domains

An integral domain is a commutative ring with unity that has no zero divisors. In other words, for all non-zero elements $a, b \in R$, if $a \cdot b = 0$, then either $a = 0$ or $b = 0$. This property is crucial as it allows for cancellation in multiplication: if $a \cdot b = a \cdot c$ and $a \neq 0$, then $b = c$.

### Euclidean Domains

A Euclidean domain is an integral domain $R$ equipped with a function $\delta: R \setminus \{0\} \to \mathbb{N} \cup \{0\}$ (called the Euclidean function) satisfying:

1. For all non-zero $a, b \in R$, $\delta(a) \leq \delta(ab)$
2. For all $a, b \in R$ with $b \neq 0$, there exist $q, r \in R$ such that $a = bq + r$ and either $r = 0$ or $\delta(r) < \delta(b)$

The second property is known as the Euclidean division algorithm, which is a generalization of the division algorithm for integers. This algorithm allows us to perform division with remainders in the domain.

#### Examples of Euclidean Domains

1. The integers $\mathbb{Z}$ with $\delta(a) = |a|$
2. The polynomial ring $F[x]$ over a field $F$ with $\delta(p) = \deg(p)$

### Euclidean Division

Euclidean division is the process of dividing one integer by another to produce a quotient and a remainder. In the context of modular arithmetic, we're particularly interested in the remainder.

For integers $a$ and $b$ with $b \neq 0$, there exist unique integers $q$ (quotient) and $r$ (remainder) such that:

$a = bq + r$, where $0 \leq r < |b|$

#### Euclidean Division Algorithm

Here's a pseudocode algorithm for Euclidean division:

```
function euclidean_division(a, b):
    if b == 0:
        error "Division by zero"
    q = floor(a / b)
    r = a - b * q
    if r < 0:
        if b > 0:
            q = q - 1
            r = r + b
        else:
            q = q + 1
            r = r - b
    return (q, r)
```

In $\mathbb{Z}_5$, we're primarily concerned with the remainder $r$, which will always be in the set $\{0, 1, 2, 3, 4\}$.

### Extended Euclidean Division

The extended Euclidean Division is a way to compute the greatest common divisor (GCD) of two numbers $a$ and $b$, and also find the coefficients of Bézout's identity, which states that:

$\gcd(a,b) = ax + by$

for some integers $x$ and $y$.

#### Extended Euclidean Division Algorithm

```
function extended_euclidean_division(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        (gcd, x', y') = extended_gcd(b, a mod b)
        x = y'
        y = x' - floor(a / b) * y'
        return (gcd, x, y)
```

This algorithm not only computes the GCD but also finds the coefficients $x$ and $y$ in Bézout's identity.
