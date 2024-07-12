## Field Extensions and Towers over Finite Fields

Let $p$ be a prime number. We'll consider field extensions over $\mathbb{Z}_p = \mathbb{F}_p$, the finite field with $p$ elements.

### Basic Definitions

1. **Automorphism**: An automorphism of a field $F$ is a bijective ring homomorphism from $F$ to itself. The set of all automorphisms of $F$ forms a group under composition.

2. **Endomorphism**: An endomorphism of a field $F$ is a ring homomorphism from $F$ to itself. Unlike automorphisms, endomorphisms are not necessarily bijective.

3. **Frobenius Endomorphism**: In a field of characteristic $p$, the map $\phi: x \mapsto x^p$ is an endomorphism called the Frobenius endomorphism. In finite fields, it's always an automorphism.

### Field Extensions

A field extension $E/F$ is a field $E$ containing $F$ as a subfield. The degree of the extension, denoted $[E:F]$, is the dimension of $E$ as a vector space over $F$.

For a finite field $\mathbb{F}_p$, we can construct extensions $\mathbb{F}_{p^n}$ of degree $n$ over $\mathbb{F}_p$.

**Example in $\mathbb{Z}_5$:**
Let's construct $\mathbb{F}_{25}$ as an extension of $\mathbb{F}_5$.

1. Choose an irreducible polynomial $f(x) = x^2 + 2 \in \mathbb{F}_5[x]$.
2. $\mathbb{F}_{25} = \mathbb{F}_5[x]/(f(x)) = \{ax + b \mid a,b \in \mathbb{F}_5\}$
3. Arithmetic in $\mathbb{F}_{25}$ is performed modulo $f(x)$.

For instance, in $\mathbb{F}_{25}$:

$(3x + 4) * (2x + 1) = 6x^2 + 3x + 8x + 4 = 6x^2 + 11x + 4 \equiv 6(3) + x + 4 \equiv 3x + 4 \pmod{x^2 + 2}$

### Towers of Field Extensions

A tower of field extensions is a sequence of fields $F_1 \subset F_2 \subset \ldots \subset F_n$ where each $F_{i+1}/F_i$ is a field extension.

**General construction for $\mathbb{F}_{p^n}$:**
We can build $\mathbb{F}_{p^n}$ as a tower of extensions over $\mathbb{F}_p$:

$\mathbb{F}_p \subset \mathbb{F}_{p^k} \subset \mathbb{F}_{p^m} \subset \mathbb{F}_{p^n}$

where $k|m|n$.

**Example tower in $\mathbb{Z}_5$:**
Let's construct $\mathbb{F}_{625} = \mathbb{F}_5^4$ as a tower:

$\mathbb{F}_5 \subset \mathbb{F}_{25} \subset \mathbb{F}_{625}$

1. $\mathbb{F}_{25} = \mathbb{F}_5[x]/(x^2 + 2)$ as before
2. $\mathbb{F}_{625} = \mathbb{F}_{25}[y]/(y^2 + y + 2)$

In this tower:
- $[\mathbb{F}_{25} : \mathbb{F}_5] = 2$
- $[\mathbb{F}_{625} : \mathbb{F}_{25}] = 2$

By the tower law: $[\mathbb{F}_{625} : \mathbb{F}_5] = 2 * 2 = 4$

### Algebraicity

This is a topic that is advanced even for the scope of this revision, but it becomes important to consider later, and is a key concept of Galois theory. Given an extension $E \supset F$ and an element $\vartheta\in E$, the following conditions are equivalent:

- $\vartheta$ is a root of $f(t)\neq\mathbf{0}\in F[t]$
- $\{1,\vartheta, \vartheta^2,\cdots\}$ are linearly independent on $F$;
- $F[\vartheta]$ is a field

$\vartheta$ is called algebraic over $F$ if any of these conditions are met (and thus all of them). An extension $E\subset F$ is algebraic iff $\forall \vartheta\in E,\vartheta$ is algebraic. Also if $[E : F] < \infty$, $E$ is algebraic over $F$.

You can also show that for $\vartheta\in E$, if $f(\vartheta)=0$ for $f(t) = a_0+a_1t+\cdots+a_{n-1}t^{n-1}+a_nt^n$ with $a_i\in E$ algebraic, then $\vartheta$ is algebraic over $F$, aka addition and multiplication preserve algebraicity.

For prime order fields, all this means is that there is a unique (up to isomorphism) extension field $\mathbb{F}_q\supseteq \mathbb{F}_p$ of degree $[\mathbb{F}_q : \mathbb{F}_p]=r$ and order $q=p^r$. Namely:

$$\overline{\mathbb{F}}_p \triangleq \bigcup_{r=1}^\infty \mathbb{F}_{p^r}$$

Defining a morphism or curve, for example, over the algebraic closure of a finite field is a concise way to say that we're interested in points lying in all valid extensions that satisfy the curve equation, and that the mapping or what not behaves similarly for all of them.

### Automorphisms and the Frobenius Endomorphism

In $\mathbb{F}_{p^n}$, the Frobenius endomorphism $\phi: x \mapsto x^p$ is an automorphism, and its powers generate the Galois group of $\mathbb{F}_{p^n}$ over $\mathbb{F}_p$.

**Example in $\mathbb{F}_{25}$ over $\mathbb{F}_5$:**
The Frobenius automorphism $\phi$ on $\mathbb{F}_{25} = \mathbb{F}_5[x]/(x^2 + 2)$ is:

$\phi(ax + b) = (ax + b)^5 = a^5x^5 + b^5 = ax^5 + b \equiv a(3x) + b \pmod{x^2 + 2}$

The Galois group $\text{Gal}(\mathbb{F}_{25}/\mathbb{F}_5) = \{\text{id}, \phi\}$ is cyclic of order 2.


