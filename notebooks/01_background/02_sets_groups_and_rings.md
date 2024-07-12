## Set Theory

Set theory forms the bedrock of modern mathematics. It provides us with a language to discuss collections of objects and the 
relationships between them. For a more in-depth treatment of set theory, Halmos' "Naive Set Theory" and Suppes' "Axiomatic Set Theory" 
are superb resources.

### Basic Definitions

1. A set is a collection of distinct objects, called elements or members of the set.
2. If $a$ is an element of set $A$, we write $a \in A$.
3. The empty set, denoted $\varnothing$, is the unique set with no elements.
4. A set $A$ is a subset of set $B$, denoted $A \subseteq B$, if every element of $A$ is also an element of $B$.
5. Every set $A \subseteq A$, or in other words, every set is contained by itself.

### Set Operations

Set theory defines several operations on sets:

1. Union: $A \cup B = \{x : x \in A \text{ or } x \in B\}$
   The union of two sets contains all elements that are in either set.

2. Intersection: $A \cap B = \{x : x \in A \text{ and } x \in B\}$
   The intersection contains all elements common to both sets.

3. Difference: $A \setminus B = \{x : x \in A \text{ and } x \notin B\}$
   The difference contains elements in $A$ but not in $B$.

4. Symmetric Difference: $A \triangle B = (A \setminus B) \cup (B \setminus A)$
   This operation results in elements that are in either set, but not in both.

### Cartesian Product

The Cartesian product of two sets $A$ and $B$, denoted $A \times B$, is the set of all ordered pairs where the first element comes 
from $A$ and the second from $B$:

$$A \times B = \{(a,b) : a \in A \text{ and } b \in B\}$$

### Functions

A function $f$ from set $A$ to set $B$, denoted $f: A \to B$, is a rule that assigns to each element of $A$ exactly one element of $B$. 
We call $A$ the domain and $B$ the codomain of $f$. The set of all $f(a)$ for $a \in A$ is called the range of $f$.

Functions can have special properties:

1. Injective (one-to-one): $\forall a_1, a_2 \in A, f(a_1) = f(a_2) \implies a_1 = a_2$
2. Surjective (onto): $\forall b \in B, \exists a \in A : f(a) = b$
3. Bijective: Both injective and surjective

### Cardinality

The cardinality of a set $A$, denoted $|A|$, is the number of elements in $A$ if $A$ is finite. For infinite sets, cardinality 
becomes more complex:

- Countably infinite: A set with the same cardinality as the natural numbers, denoted $\aleph_0$.
- Uncountable: An infinite set that is not countably infinite, such as the real numbers, with cardinality denoted $\mathfrak{c}$.

---

## Group Theory

Group theory is the study of symmetries and algebraic structures. Professor Macauley's Visual Group Theory lectures on YouTube 
and Nathan Carter's "Visual Group Theory" book provide a beautiful and approachable exposition. Saracino's "Abstract Algebra" 
is approachable but in need of fresh typesetting. Lang's "Algebra" is also a good resource here and more generally on rings and 
fields to come.

### Groups

A group is an ordered pair $(\mathbb{G}, *)$ where $\mathbb{G}$ is a set and $*$ is a binary operation on $\mathbb{G}$ satisfying 
four axioms:

1. Closure: $\forall a, b \in \mathbb{G}, a * b \in \mathbb{G}$
2. Associativity: $\forall a, b, c \in \mathbb{G}, (a * b) * c = a * (b * c)$
3. Identity: $\exists e \in \mathbb{G}, \forall a \in \mathbb{G}: a * e = e * a = a$
4. Inverse: $\forall a \in \mathbb{G}, \exists a^{-1} \in \mathbb{G}: a * a^{-1} = a^{-1} * a = e$

The identity element is often denoted as $e$, and the inverse of an element $a$ is written as $a^{-1}$. We also have "subtraction" defined through the binary operator of the inverse of an element.

### Abelian Groups

An Abelian group, named after Norwegian mathematician Niels Henrik Abel, is a group which is commutative under the binary operation $*$. A group $\mathbb{G}$ is abelian if $a * b = b * a, \forall a, b \in \mathbb{G}$.

### Finite Groups

A group $\mathbb{G}$ is finite if the number of elements in $\mathbb{G}$ is finite, which then has cardinality or order $|\mathbb{G}|$.

### Lagrange's Theorem

For a finite group $\mathbb{G}$ with $a \in \mathbb{G}$ and let there exist a positive integer $d$ such that $a^d$ is the smallest positive power of $a$ that is equal to $e$, the identity of the group. Let $n = |\mathbb{G}|$ be the order of $\mathbb{G}$, and let $d$ be the order of $a$, then $a^n = e$ and $d \mid n$.

### Subgroups

A subset $H$ of a group $\mathbb{G}$ is a subgroup if it forms a group under the same operation as $\mathbb{G}$. We denote this as $H \leq \mathbb{G}$. The order of a subgroup always divides the order of the group (Lagrange's Theorem). Similar to a set, every group $\mathbb{G} \subseteq \mathbb{G}$, and for every group there is a trivial subgroup containing only the identity.

### Homomorphisms and Isomorphisms

A function $f: G \to H$ between groups is a homomorphism if it preserves the group operation: $f(ab) = f(a)f(b) \forall a,b \in G$.

An isomorphism is a bijective homomorphism. If there exists an isomorphism between groups $G$ and $H$, we say they are isomorphic and write $G \cong H$.

### Cosets and Normal Subgroups

For a subgroup $H$ of $G$ and an element $a \in G$, we define:

- Left coset: $aH = \{ah : h \in H\}$
- Right coset: $Ha = \{ha : h \in H\}$

A subgroup $N$ of $G$ is called normal if $gN = Ng \forall g \in G$. We denote this as $$N \triangleleft G$$.

### Cyclic Groups

A group $\mathbb{G}$ is cyclic if there exists an element $g \in \mathbb{G}$ such that every element of $\mathbb{G}$ can be written as a power of $g$:

$$\mathbb{G} = \langle g \rangle = \{g^n : n \in \mathbb{Z}\}$$

Here, $g$ is called a generator of $\mathbb{G}$. Cyclic groups have several important properties:

1. Every element $x \in \mathbb{G}$ can be written as $x = g^n$ for some integer $n$.
2. If $\mathbb{G}$ is infinite, it is isomorphic to $(\mathbb{Z}, +)$.
3. If $\mathbb{G}$ is finite with $|\mathbb{G}| = n$, it is isomorphic to $(\mathbb{Z}/n\mathbb{Z}, +)$.
4. All cyclic groups are Abelian.
5. Subgroups of cyclic groups are cyclic.
6. The order of $\mathbb{G}$ is the smallest positive integer $m$ such that $g^m = e$.

### Quotient Groups

If $N \triangleleft G$, we can form the quotient group $G/N$, whose elements are the cosets of $N$ in $G$.

---

## Ring Theory

### Rings

A ring $(R, +, \cdot)$ is an algebraic structure consisting of a set $R$ with two binary operations, addition $(+)$ and multiplication $(\cdot)$, satisfying the following axioms:

1. $(R, +)$ is an abelian group:
   - Closure: $\forall a, b \in R, a + b \in R$
   - Associativity: $\forall a, b, c \in R, (a + b) + c = a + (b + c)$
   - Commutativity: $\forall a, b \in R, a + b = b + a$
   - Identity: $\exists 0 \in R, \forall a \in R, a + 0 = 0 + a = a$
   - Inverse: $\forall a \in R, \exists (-a) \in R, a + (-a) = (-a) + a = 0$

2. $(R, \cdot)$ is a monoid:
   - Closure: $\forall a, b \in R, a \cdot b \in R$
   - Associativity: $\forall a, b, c \in R, (a \cdot b) \cdot c = a \cdot (b \cdot c)$

3. Distributivity:
   - Left distributivity: $\forall a, b, c \in R, a \cdot (b + c) = (a \cdot b) + (a \cdot c)$
   - Right distributivity: $\forall a, b, c \in R, (a + b) \cdot c = (a \cdot c) + (b \cdot c)$

A ring is called commutative if multiplication is commutative, i.e., $\forall a, b \in R, a \cdot b = b \cdot a$. If a ring has a multiplicative identity element $1 \neq 0$ such that $\forall a \in R, 1 \cdot a = a \cdot 1 = a$, it is called a ring with unity.

### Ideals

An ideal of a ring $R$ is a subset $I \subseteq R$ where:

1. $(I,+)$ is a subgroup of $(R,+)$, meaning:
   a. $I$ is non-empty
   b. For all $a,b \in I$, $a - b \in I$
2. For all $r \in R$ and $i \in I$, both $r \cdot i \in I$ and $i \cdot r \in I$ (absorption property)

The absorption property of ideals interacts with both ring operations, as it involves multiplication by any ring element and the result remains in the ideal.

### Quotient Rings

For a ring $R$ and ideal $I$, the quotient ring $R/I$ is defined as:

$R/I = \{r + I : r \in R\}$

where $r + I = \{r + i : i \in I\}$ is the coset of $r$ modulo $I$.

Operations in $R/I$ are defined as:

1. Addition: $(a + I) + (b + I) = (a + b) + I$
2. Multiplication: $(a + I) \cdot (b + I) = (a \cdot b) + I$

These operations are well-defined because of the ideal properties, particularly the absorption property.

### Polynomial Rings

Given a ring $R$, the polynomial ring $R[x]$ is defined as the set of all formal sums of the form:

$$f(x) = \sum_{i=0}^n a_i x^i = a_0 + a_1x + a_2x^2 + ... + a_nx^n$$

where:

1. $n \in \mathbb{Z^+}$
2. $a_i \in R$ (called coefficients)
3. $x$ is an indeterminate (or variable)
4. Only finitely many $a_i$ are non-zero

The ring structure of $R[x]$ is defined by the following operations:

1. Addition: For $f(x) = \sum a_ix^i$ and $g(x) = \sum b_ix^i$,

   $(f + g)(x) = \sum_{i=0}^{\max(\deg(f),\deg(g))} (a_i + b_i)x^i$

2. Multiplication: For $f(x) = \sum a_ix^i$$ and $$g(x) = \sum b_ix^i$,

   $(f \cdot g)(x) = \sum_{k=0}^{\deg(f)+\deg(g)} (\sum_{i+j=k} a_ib_j)x^k$

Key properties:

1. The zero polynomial, denoted $0$, has all coefficients equal to $0$.
2. If $R$ has a unity $1 \neq 0$, then $R[x]$ has a unity, which is the constant polynomial $1$.
3. $R$ is embedded in $R[x]$ as the set of constant polynomials.
4. If $R$ is commutative, then $R[x]$ is commutative.
5. The degree of a non-zero polynomial $f(x)$, denoted $\deg(f)$, is the highest power of $x$ with a non-zero coefficient.

This definition treats polynomials as formal algebraic objects, not as functions. The construction can be extended to multiple variables, e.g., $R[x,y] = (R[x])[y]$.
