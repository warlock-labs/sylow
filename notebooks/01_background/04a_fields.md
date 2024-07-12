---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.16.3
---

## Field Theory

### Fields

A field $F$ is a set with two binary operations defined over it and closed under it, usually addition ($+$) and multiplication ($\cdot$). The field $F$ must satisfy the following axioms:

1. $(F, +)$ is an abelian group with identity element $0$
2. $(F, +, \cdot)$ is a commutative ring with identity element $0$
3. $(F \setminus \{0\}, \cdot)$ is an abelian group with identity element $1$
4. Distributivity: $a \cdot (b + c) = (a \cdot b) + (a \cdot c) \forall a, b, c \in F$

Formally, a field is a commutative ring where every non-zero element has a multiplicative inverse. For every $a \in F, a \neq 0$, there exists $b \in F$ such that $a \cdot b = 1_F$.

Examples of infinite fields include the rational numbers $\mathbb{Q}$, the real numbers $\mathbb{R}$, and the complex numbers $\mathbb{C}$.

### Division in Infinite Fields

In a field $F$, division is defined for all non-zero elements. For any $a, b \in F$ with $b \neq 0$, we define:

$a \div b = a \cdot b^{-1}$

where $b^{-1}$ is the unique multiplicative inverse of $b$. This inverse always exists for non-zero elements in a field.

Every field is automatically a Euclidean domain, where we can define $\delta(a) = 0$ for all non-zero $a$. The Euclidean division algorithm simplifies in fields: for any $a, b \in F$ with $b \neq 0$, we can always find unique $q, r \in F$ such that:

$a = bq + r$

where $r = 0$, and $q = a \div b$.

### Finite Fields

Finite fields, also known as Galois fields, are fields with a finite number of elements. They are denoted $GF(q)$ or $\mathbb{F}_q$, where $q = p^n$ for some prime $p$ and positive integer $n$.

Key properties of finite fields include:

1. The order (number of elements) of a finite field is always a prime power.
2. For each prime power $q$, there exists a unique (up to isomorphism) finite field of order $q$.
3. The multiplicative group of a finite field is cyclic.

### Modular Arithmetic in $\mathbb{Z}_p$

For any prime $p$, we define the prime field $\mathbb{Z}_p$ as the set of integers modulo $p$:

$\mathbb{Z}_p = \{0, 1, 2, ..., p-1\}$

Example: In $\mathbb{Z}_5$, we have $\{0, 1, 2, 3, 4\}$.

Modular arithmetic is a system of arithmetic for finite fields and rings, where numbers "wrap around" when reaching a certain value, called the modulus.

All operations in $\mathbb{Z}_p$ are performed modulo $p$.

#### Addition and Subtraction
For $a, b \in \mathbb{Z}_p$:

$a \oplus b = (a + b) \bmod p$
$a \ominus b = (a - b) \bmod p$

Example: In $\mathbb{Z}_5$, the addition table is:

| $\oplus$ | 0 | 1 | 2 | 3 | 4 |
|---------|---|---|---|---|---|
| 0 | 0 | 1 | 2 | 3 | 4 |
| 1 | 1 | 2 | 3 | 4 | 0 |
| 2 | 2 | 3 | 4 | 0 | 1 |
| 3 | 3 | 4 | 0 | 1 | 2 |
| 4 | 4 | 0 | 1 | 2 | 3 |

#### Multiplication and Division
For $a, b \in \mathbb{Z}_p$:

$a \otimes b = (a \times b) \bmod p$

Division is defined as multiplication by the multiplicative inverse.

Example: In $\mathbb{Z}_5$, the multiplication table is:

| $\otimes$ | 0 | 1 | 2 | 3 | 4 |
|-----------|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 0 | 0 |
| 1 | 0 | 1 | 2 | 3 | 4 |
| 2 | 0 | 2 | 4 | 1 | 3 |
| 3 | 0 | 3 | 1 | 4 | 2 |
| 4 | 0 | 4 | 3 | 2 | 1 |

In finite fields, division is performed as follows:

1. For prime fields $\mathbb{F}_p$: $a \div b = a \cdot b^{-1} \pmod{p}$
2. For extension fields $\mathbb{F}_{p^n}$: $a(x) \div b(x) = a(x) \cdot b(x)^{-1} \pmod{f(x)}$

where $f(x)$ is the irreducible polynomial used to construct $\mathbb{F}_{p^n}$. In both cases, the multiplicative inverse can be computed using the Extended Euclidean Algorithm.

#### Euler's Totient Function

Euler's Totient Function, denoted as $\phi(n)$ or $\varphi(n)$, counts the number of positive integers up to $n$ that are relatively prime to $n$ (i.e., their greatest common divisor with $n$ is 1).

##### Definition

For a positive integer $n$, $\phi(n)$ is the count of numbers $k$ in the range $1 \leq k < n$ where $\gcd(k,n) = 1$.

##### Formula

For a positive integer $n$ with prime factorization $n = p_1^{a_1} \cdot p_2^{a_2} \cdot ... \cdot p_k^{a_k}$:

$$\phi(n) = n \prod_{i=1}^k (1 - \frac{1}{p_i})$$

##### Properties

1. For a prime number $p$, $\phi(p) = p - 1$
2. $\phi$ is multiplicative: if $\gcd(a,b) = 1$, then $\phi(ab) = \phi(a) \cdot \phi(b)$
3. For a prime power $p^k$, $\phi(p^k) = p^k - p^{k-1} = p^k(1 - \frac{1}{p})$

##### Examples

1. $\phi(10) = 4$, as 1, 3, 7, 9 are relatively prime to 10
2. $\phi(12) = 4$, as 1, 5, 7, 11 are relatively prime to 12
3. $\phi(15) = 8$, as 1, 2, 4, 7, 8, 11, 13, 14 are relatively prime to 15

##### Calculation Method

1. Find the prime factorization of $n$
2. For each prime factor $p$, multiply $n$ by $(1 - \frac{1}{p})$
3. The result is $\phi(n)$

#### Fermat's Little Theorem and Euler's Theorem

Fermat's Little Theorem states that for any integer $a$ not divisible by $p$:

$a^{p-1} \equiv 1 \pmod{p}$

Example: In $\mathbb{Z}_5$, for any non-zero $a$, $a^4 \equiv 1 \pmod{5}$

We can verify this using the multiplication table:
- $1^4 = 1 \equiv 1 \pmod{5}$
- $2^4 = 2 \otimes 2 \otimes 2 \otimes 2 = 4 \otimes 2 \otimes 2 = 3 \otimes 2 = 1 \pmod{5}$
- $3^4 = 3 \otimes 3 \otimes 3 \otimes 3 = 2 \otimes 3 \otimes 3 = 1 \otimes 3 = 3 \pmod{5}$
- $4^4 = 4 \otimes 4 \otimes 4 \otimes 4 = 1 \otimes 4 \otimes 4 = 4 \otimes 4 = 1 \pmod{5}$

Applications:
1. Finding multiplicative inverses: $a^{-1} \equiv a^{p-2} \pmod{p}$
   Example: In $\mathbb{Z}_5$, $3^{-1} \equiv 3^3 \equiv 2 \pmod{5}$
2. Efficient exponentiation: $a^n \equiv a^{n \bmod (p-1)} \pmod{p}$ for $a \neq 0$
   Example: In $\mathbb{Z}_5$, $3^{10} \equiv 3^{10 \bmod 4} \equiv 3^2 \equiv 4 \pmod{5}$

#### Congruences and Residue Classes

In $\mathbb{Z}_p$, two integers $a$ and $b$ are congruent if:

$a \equiv b \pmod{p}$

The residue classes in $\mathbb{Z}_p$ are:

$[i] = \{... , i-p, i, i+p, i+2p, ...\}$ for $i = 0, 1, ..., p-1$

Example: In $\mathbb{Z}_5$, the residue classes are:
- $[0] = \{\ldots, -5, 0, 5, 10, \ldots\}$
- $[1] = \{\ldots, -4, 1, 6, 11, \ldots\}$
- $[2] = \{\ldots, -3, 2, 7, 12, \ldots\}$
- $[3] = \{\ldots, -2, 3, 8, 13, \ldots\}$
- $[4] = \{\ldots, -1, 4, 9, 14, \ldots\}$

#### Coprime Numbers

Two integers $a$ and $b$ are considered coprime (or relatively prime) if their greatest common divisor (GCD) is $1$. In other words:

$$\gcd(a,b) = 1$$

Some key properties of coprime numbers include:

1. If $a$ and $b$ are coprime, there exist integers $x$ and $y$ such that:

   $$ax + by = 1$$

   This is known as Bézout's identity.

2. If $a$ and $b$ are coprime, then:

   $$(a \bmod b) \text{ has a multiplicative inverse modulo } b$$

   This means there exists an integer $x$ such that:

   $$ax \equiv 1 \pmod{b}$$

3. The product of coprime numbers is coprime to each of the original numbers.

To find coprime numbers, one can use the Euclidean algorithm to compute the GCD. If the GCD is 1, the numbers are coprime. For example:

- 8 and 15 are coprime because $\gcd(8,15) = 1$
- 14 and 21 are not coprime because $\gcd(14,21) = 7$

In the context of the Chinese remainder theorem, coprimality is a crucial requirement. The CRT states that if we have a system of congruences with coprime moduli:

$$x \equiv a_1 \pmod{m_1}$$
$$x \equiv a_2 \pmod{m_2}$$
$$\vdots$$
$$x \equiv a_k \pmod{m_k}$$

where all $m_i$ are pairwise coprime, then there exists a unique solution modulo $M = m_1 \cdot m_2 \cdot ... \cdot m_k$.

#### Chinese Remainder Theorem

The Chinese Remainder Theorem (CRT) states that if one has a system of congruences with coprime moduli, there exists a unique solution modulo the product of the moduli.
Given a system of congruences:

$x \equiv a_1 \pmod{m_1}$
$x \equiv a_2 \pmod{m_2}$
$\vdots$
$x \equiv a_k \pmod{m_k}$

Where all $m_i$ are pairwise coprime, there exists a unique solution $x$ modulo $M = m_1 * m_2 * ... * m_k$.
The solution can be constructed as:
$x = \sum_{i=1}^k a_i * M_i * y_i \pmod{M}$
where $M_i = M / m_i$ and $y_i = M_i^{-1} \pmod{m_i}$.

### Polynomial Modular Arithmetic in $\mathbb{Z}_p[x]$

Polynomial modular arithmetic in prime fields combines concepts from modular arithmetic and polynomial arithmetic over finite fields. Let $\mathbb{F}_p$ be a prime field with $p$ elements, where $p$ is prime.

#### Polynomial Ring $\mathbb{F}_p[x]$

The polynomial ring $\mathbb{F}_p[x]$ consists of all polynomials with coefficients from $\mathbb{F}_p$. A general element of $\mathbb{F}_p[x]$ has the form:

$$f(x) = a_nx^n + a_{n-1}x^{n-1} + \cdots + a_1x + a_0$$

where $a_i \in \mathbb{F}_p$ for all $i$.

### Basic Operations

1. Addition and Subtraction:
   For $f(x) = \sum a_ix^i$ and $g(x) = \sum b_ix^i$,
   $(f + g)(x) = \sum (a_i \oplus b_i)x^i$
   $(f - g)(x) = \sum (a_i \ominus b_i)x^i$

2. Multiplication:
   $(f \cdot g)(x) = \sum (\sum a_i \otimes b_j)x^{i+j}$

3. Division with Remainder:
   For $f(x)$ and $g(x) \neq 0$, there exist unique $q(x)$ and $r(x)$ such that:
   $f(x) = g(x)q(x) + r(x)$, where $\deg(r) < \deg(g)$

### Modular Reduction

When working with polynomials modulo another polynomial $m(x)$, we perform operations and then reduce the result modulo $m(x)$. This is denoted as:

$f(x) \equiv g(x) \pmod{m(x)}$

which means $m(x)$ divides $f(x) - g(x)$.

### Examples

1. In $\mathbb{Z}_5[x]$ mod $(x^2 + 1)$:
   $(x + 1)^2 \equiv x^2 + 2x + 1 \equiv 2x + 2$

2. In $\mathbb{Z}_5[x]$ mod $(x^2 + 2)$:
   $(2x + 1)(x + 2) \equiv 2x^2 + 4x + x + 2 \equiv 2x^2 + 2x + 2 \equiv 3x + 3$

### Irreducible Polynomials

A polynomial $f(x) \in \mathbb{Z}_p[x]$ is irreducible if it cannot be factored into the product of two non-constant polynomials in $\mathbb{Z}_p[x]$. Irreducible polynomials are crucial for constructing finite field extensions.

For example, $x^2 + 1$ is irreducible in $\mathbb{Z}_5[x]$ but reducible in $\mathbb{Z}_3[x]$ as $x^2 + 1 \equiv (x + 1)(x + 2) \pmod{3}$.

### Subfields

#### Definition

A subfield of a field $F$ is a subset $K \subseteq F$ that is itself a field under the operations of $F$. More formally, $K$ is a subfield of $F$ if:

1. $K$ is a subset of $F$
2. $K$ is closed under the addition and multiplication operations of $F$
3. $K$ contains the additive and multiplicative identities of $F$
4. Every element in $K$ has an additive inverse in $K$
5. Every non-zero element in $K$ has a multiplicative inverse in $K$

#### Properties

1. **Minimal Subfield**: Every field $F$ contains a unique smallest subfield, called the prime subfield. It is isomorphic to either $\mathbb{Q}$ (if $F$ has characteristic 0) or $\mathbb{F}_p$ (if $F$ has characteristic $p$).

2. **Tower Law**: If $E$ is a subfield of $F$ and $F$ is a subfield of $K$, then $[K:E] = [K:F][F:E]$.

3. **Degree of Subfield**: If $K$ is a subfield of $F$, then $[F:K]$ divides $[F:\mathbb{F}_p]$ where $\mathbb{F}_p$ is the prime subfield of $F$.

4. **Galois Correspondence**: In a Galois extension $F/K$, there is a one-to-one correspondence between the subfields of $F$ containing $K$ and the subgroups of the Galois group $\text{Gal}(F/K)$.

#### Examples

1. **Subfields of $\mathbb{C}$**: 
   - $\mathbb{Q} \subset \mathbb{R} \subset \mathbb{C}$
   - $\mathbb{Q}(\sqrt{2}) \subset \mathbb{R}$
   - $\mathbb{Q}(i) \subset \mathbb{C}$

2. **Subfields of Finite Fields**:
   Let $\mathbb{F}_{p^n}$ be a finite field. Then $\mathbb{F}_{p^m}$ is a subfield of $\mathbb{F}_{p^n}$ if and only if $m$ divides $n$.

   Example: Subfields of $\mathbb{F}_{2^4}$
   - $\mathbb{F}_2 \subset \mathbb{F}_{2^4}$
   - $\mathbb{F}_{2^2} \subset \mathbb{F}_{2^4}$

3. **Algebraic Number Fields**:
   Consider $\mathbb{Q}(\sqrt{2}, \sqrt{3})$. Its subfields include:
   - $\mathbb{Q}$
   - $\mathbb{Q}(\sqrt{2})$
   - $\mathbb{Q}(\sqrt{3})$
   - $\mathbb{Q}(\sqrt{6})$

