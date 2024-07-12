## Elliptic Curves

### Definition and Basic Properties

An elliptic curve $E$ over a field $K$ is a smooth, projective algebraic curve of genus one, with a specified point $O$. In characteristic not 2 or 3, every elliptic curve can be written in short Weierstrass form:

$E: y^2 = x^3 + ax + b$

where $a, b \in K$, and the discriminant $\Delta = -16(4a^3 + 27b^2) \neq 0$.

#### The Point at Infinity

The point $O$, called the point at infinity, serves as the identity element for the group law. In projective coordinates, it can be represented as $[0:1:0]$.

#### Affine and Projective Representations

- Affine form: $E = \{(x,y) \in K^2 : y^2 = x^3 + ax + b\} \cup \{O\}$
- Projective form: $E = \{[X:Y:Z] \in \mathbb{P}^2(K) : Y^2Z = X^3 + aXZ^2 + bZ^3\}$

### Group Law

Elliptic curves have an abelian group structure, with the point at infinity $O$ serving as the identity element.

#### Geometric Interpretation

For points $P, Q$ on $E$:

1. $O + P = P$ for all $P$
2. If $P = (x, y)$, then $P + (x, -y) = O$ (inverse)
3. To add $P$ and $Q$ (chord rule):
   - Draw a line through $P$ and $Q$
   - Find the third intersection point $R$ with $E$
   - Reflect $R$ across the x-axis to get $P + Q$
4. To double $P$ (tangent rule):
   - Draw the tangent line to $E$ at $P$
   - Find the second intersection point $R$ with $E$
   - Reflect $R$ across the x-axis to get $2P$

#### Algebraic Formulas

For $P_1 = (x_1, y_1)$ and $P_2 = (x_2, y_2)$, $P_3 = (x_3, y_3) = P_1 + P_2$:

If $P_1 \neq P_2$:
$x_3 = \lambda^2 - x_1 - x_2$
$y_3 = \lambda(x_1 - x_3) - y_1$
where $\lambda = \frac{y_2 - y_1}{x_2 - x_1}$

If $P_1 = P_2$:
$x_3 = \lambda^2 - 2x_1$
$y_3 = \lambda(x_1 - x_3) - y_1$
where $\lambda = \frac{3x_1^2 + a}{2y_1}$

### Scalar Multiplication

For a point $P$ on $E$ and an integer $n$, scalar multiplication $[n]P$ is defined as:

$[n]P = \underbrace{P + P + \cdots + P}_{n \text{ times}}$

This operation is fundamental in elliptic curve cryptography.

#### Double-and-Add Algorithm

An efficient method to compute $[n]P$:

1. Convert $n$ to binary: $n = \sum_{i=0}^k b_i 2^i$
2. Initialize $Q = O$
3. For $i$ from $k$ down to 0:
   - $Q = 2Q$
   - If $b_i = 1$, $Q = Q + P$
4. Return $Q$

### Elliptic Curves over Finite Fields

When the field $K$ is finite (typically $\mathbb{F}_p$ or $\mathbb{F}_{2^m}$), the elliptic curve $E(K)$ forms a finite abelian group.

#### Order of the Curve

The number of points on $E(\mathbb{F}_q)$, denoted $\#E(\mathbb{F}_q)$, satisfies the Hasse bound:

$q + 1 - 2\sqrt{q} \leq \#E(\mathbb{F}_q) \leq q + 1 + 2\sqrt{q}$

#### Structure Theorem

For an elliptic curve $E$ over $\mathbb{F}_q$:

$E(\mathbb{F}_q) \cong \mathbb{Z}/n_1\mathbb{Z} \oplus \mathbb{Z}/n_2\mathbb{Z}$

where $n_1 | n_2$ and $n_1 | q - 1$.

## Pairings

Bilinear pairings on elliptic curves are crucial for many advanced cryptographic protocols.

#### Weil Pairing

For an elliptic curve $E$ over $\mathbb{F}_q$ and a prime $l | \#E(\mathbb{F}_q)$, the Weil pairing is a map:

$e: E[l] \times E[l] \to \mu_l$

where $E[l]$ is the $l$-torsion subgroup and $\mu_l$ is the group of $l$-th roots of unity in $\bar{\mathbb{F}}_q$.

Properties:
1. Bilinearity: $e([a]P, [b]Q) = e(P,Q)^{ab}$
2. Non-degeneracy: If $e(P,Q) = 1$ for all $Q \in E[l]$, then $P = O$
3. Alternating: $e(P,P) = 1$ for all $P \in E[l]$

#### Tate Pairing

The reduced Tate pairing is a more efficient alternative to the Weil pairing:

$t: E(\mathbb{F}_{q^k})[l] \times E(\mathbb{F}_{q^k})/lE(\mathbb{F}_{q^k}) \to \mathbb{F}_{q^k}^*/{(\mathbb{F}_{q^k}^*)}^l$

where $k$ is the embedding degree.


