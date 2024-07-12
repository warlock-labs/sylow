## Vector Spaces

Vector spaces are fundamental algebraic structures that generalize the notion of vectors in two or three-dimensional space to any number of dimensions.

### Definition of Vector Spaces

A vector space $V$ over a field $F$ is a set equipped with two operations:

1. Vector addition: $+: V \times V \to V$
2. Scalar multiplication: $\cdot: F \times V \to V$

These operations must satisfy the following axioms for all $u, v, w \in V$ and $a, b \in F$:

1. $(u + v) + w = u + (v + w)$ (Associativity of addition)
2. $u + v = v + u$ (Commutativity of addition)
3. $\exists 0 \in V$ such that $v + 0 = v$ for all $v \in V$ (Additive identity)
4. For each $v \in V$, $\exists (-v) \in V$ such that $v + (-v) = 0$ (Additive inverse)
5. $a(u + v) = au + av$ (Distributivity of scalar multiplication over vector addition)
6. $(a + b)v = av + bv$ (Distributivity of scalar multiplication over field addition)
7. $(ab)v = a(bv)$ (Associativity of scalar multiplication)
8. $1v = v$ where $1$ is the multiplicative identity in $F$

### Linear Independence and Basis

A set of vectors $\{v_1, \ldots, v_n\}$ in a vector space $V$ is linearly independent if the equation:

$$a_1v_1 + a_2v_2 + \cdots + a_nv_n = 0$$

implies $a_1 = a_2 = \cdots = a_n = 0$ for scalars $a_i \in F$.

A basis for a vector space $V$ is a linearly independent set of vectors that spans $V$. In other words, every vector in $V$ can be uniquely expressed as a linear combination of basis vectors.

### Dimension and Subspaces

The dimension of a vector space $V$, denoted $\dim(V)$, is the number of vectors in any basis of $V$. A finite-dimensional vector space has a finite basis, while an infinite-dimensional space does not.

A subspace $W$ of a vector space $V$ is a subset of $V$ that is itself a vector space under the operations inherited from $V$.

### Concrete Example: Vector Space over $\mathbb{Z}_5$

To illustrate these concepts, let's consider a concrete example using the finite field $\mathbb{Z}_5$ (integers modulo 5). We'll explore the vector space $V = \mathbb{Z}_5 \times \mathbb{Z}_5$, which consists of ordered pairs $(a, b)$ where $a, b \in \mathbb{Z}_5$. Our scalar field is $\mathbb{Z}_5 = \{0, 1, 2, 3, 4\}$.

#### Vector Addition

For $(a_1, b_1), (a_2, b_2) \in V$:

$$(a_1, b_1) + (a_2, b_2) = ((a_1 + a_2) \bmod 5, (b_1 + b_2) \bmod 5)$$

**Example:**
$$(2, 3) + (4, 1) = (1, 4)$$

#### Scalar Multiplication

For $c \in \mathbb{Z}_5$ and $(a, b) \in V$:

$$c \cdot (a, b) = ((ca) \bmod 5, (cb) \bmod 5)$$

**Example:**
$$3 \cdot (2, 4) = (1, 2)$$

#### Verifying Vector Space Axioms

Let's verify some of the vector space axioms using our $\mathbb{Z}_5 \times \mathbb{Z}_5$ example:

1. **Commutativity of addition:**
   $$(2, 3) + (4, 1) = (1, 4) = (4, 1) + (2, 3)$$

2. **Associativity of addition:**
   $$((2, 3) + (4, 1)) + (3, 2) = (1, 4) + (3, 2) = (4, 1)$$
   $$(2, 3) + ((4, 1) + (3, 2)) = (2, 3) + (2, 3) = (4, 1)$$

3. **Additive identity:**
   The zero vector is $(0, 0)$
   $$(2, 3) + (0, 0) = (2, 3)$$

4. **Additive inverse:**
   For $(2, 3)$, the additive inverse is $(3, 2)$
   $$(2, 3) + (3, 2) = (0, 0)$$

5. **Distributivity of scalar multiplication over vector addition:**
   $$3 \cdot ((2, 1) + (4, 3)) = 3 \cdot (1, 4) = (3, 2)$$
   $$3 \cdot (2, 1) + 3 \cdot (4, 3) = (1, 3) + (2, 4) = (3, 2)$$

#### Linear Independence and Basis in $\mathbb{Z}_5 \times \mathbb{Z}_5$

In $\mathbb{Z}_5 \times \mathbb{Z}_5$, the vectors $(1, 0)$ and $(0, 1)$ form a basis. They are linearly independent because:

$$a(1, 0) + b(0, 1) = (0, 0)$$

implies $a = b = 0$ in $\mathbb{Z}_5$.

Every vector in $\mathbb{Z}_5 \times \mathbb{Z}_5$ can be uniquely expressed as a linear combination of these basis vectors:

$$(a, b) = a(1, 0) + b(0, 1)$$

#### Subspaces of $\mathbb{Z}_5 \times \mathbb{Z}_5$

Some examples of subspaces in $\mathbb{Z}_5 \times \mathbb{Z}_5$ include:

1. $\{(0, 0)\}$: The trivial subspace
2. $\{(a, 0) \mid a \in \mathbb{Z}_5\}$: A one-dimensional subspace
3. $\mathbb{Z}_5 \times \mathbb{Z}_5$ itself: The entire space

#### Dimension of $\mathbb{Z}_5 \times \mathbb{Z}_5$

The dimension of $\mathbb{Z}_5 \times \mathbb{Z}_5$ is 2, as it has a basis with two vectors. This means that any set of three or more vectors in $\mathbb{Z}_5 \times \mathbb{Z}_5$ must be linearly dependent.

## Algebraic Varieties

Algebraic varieties are fundamental objects in algebraic geometry, providing a geometric perspective on solutions to systems of polynomial equations. We'll explore their definition, types, and key properties.

### Definition of Algebraic Varieties

Let $k$ be an algebraically closed field, and let $k[x_1, \ldots, x_n]$ be the ring of polynomials in $n$ variables over $k$.

**Definition 1 (Affine Algebraic Set):** For a set of polynomials $S \subset k[x_1, \ldots, x_n]$, we define the affine algebraic set $V(S)$ as:

$$V(S) = \{(a_1, \ldots, a_n) \in k^n : f(a_1, \ldots, a_n) = 0 \text{ for all } f \in S\}$$

**Definition 2 (Algebraic Variety):** An algebraic variety is an irreducible algebraic set. That is, it cannot be written as the union of two proper algebraic subsets.

For any subset $X \subset k^n$, we define the ideal of $X$ as:

$$I(X) = \{f \in k[x_1, \ldots, x_n] : f(a_1, \ldots, a_n) = 0 \text{ for all } (a_1, \ldots, a_n) \in X\}$$

**Theorem 1 (Hilbert's Nullstellensatz):** For any ideal $I \subset k[x_1, \ldots, x_n]$,

$$I(V(I)) = \sqrt{I}$$

where $\sqrt{I}$ is the radical of $I$.

This theorem establishes a fundamental correspondence between algebraic sets and radical ideals.

### Affine and Projective Varieties

#### Affine Varieties

An affine variety is an algebraic variety in affine space $k^n$.

**Example:** The parabola $y = x^2$ in $k^2$ is an affine variety defined by the polynomial $f(x,y) = y - x^2$.

#### Projective Varieties

To define projective varieties, we first introduce projective space:

**Definition 3 (Projective Space):** The projective $n$-space over $k$, denoted $\mathbb{P}^n(k)$ or simply $\mathbb{P}^n$, is defined as:

$$\mathbb{P}^n = (k^{n+1} \setminus \{0\}) / \sim$$

where $\sim$ is the equivalence relation $(x_0, \ldots, x_n) \sim (\lambda x_0, \ldots, \lambda x_n)$ for any $\lambda \in k^*$.

A projective variety is an algebraic variety in projective space $\mathbb{P}^n$.

**Definition 4 (Projective Variety):** For a set of homogeneous polynomials $S \subset k[x_0, \ldots, x_n]$, we define the projective algebraic set $V(S)$ as:

$$V(S) = \{[a_0 : \ldots : a_n] \in \mathbb{P}^n : f(a_0, \ldots, a_n) = 0 \text{ for all } f \in S\}$$

A projective variety is an irreducible projective algebraic set.

**Example:** The projective conic $x^2 + y^2 = z^2$ in $\mathbb{P}^2$ is a projective variety.

### Coordinate Rings

The coordinate ring of an algebraic variety encodes its algebraic structure.

**Definition 5 (Coordinate Ring):** For an affine variety $X \subset k^n$, the coordinate ring of $X$ is:

$$k[X] = k[x_1, \ldots, x_n] / I(X)$$

For a projective variety $X \subset \mathbb{P}^n$, we define the homogeneous coordinate ring as:

$$S(X) = k[x_0, \ldots, x_n] / I(X)$$

where $I(X)$ is the homogeneous ideal of polynomials vanishing on $X$.

### Properties of Algebraic Varieties

1. **Dimension:** The dimension of an algebraic variety $X$ is defined as the transcendence degree of its function field $k(X)$ over $k$.

2. **Singular Points:** A point $p$ on a variety $X$ is singular if the rank of the Jacobian matrix at $p$ is less than the dimension of $X$.

3. **Zariski Topology:** The Zariski topology on $k^n$ or $\mathbb{P}^n$ is defined by taking algebraic sets as closed sets. This topology is fundamental in algebraic geometry.

4. **Morphisms:** A morphism between varieties $X \subset k^m$ and $Y \subset k^n$ is a function $\phi: X \to Y$ such that each component is given by a polynomial function.
