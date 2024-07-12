---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.16.3
---

## Implementation considerations

### Scalar definition

We need multiprecision arithmetic because of the sheer size of these numbers. This section outlines performance considerations when dealing an implementation of these arithemtics.

For a 256-bit prime modulus, the decomposition of this into 4 64-bit limbs/words/branches/fields optimizes the arithmetic beacuse of the fact that each limb fits natively into 64-bit cpu registers. The general idea for squaring / multiplying 4-limb elements is that the operation produces an 8-limb element, which could be considered as a `long` type, with any potential overflow of the 4 or 8 limb element being treated by a carry bit. There are, apparently constant time functions that exist for comparisons and modulo addition and subtraction too in this representation. Since these operations happen extremely frequently, they need to be optimized as much as possible. 

#### Coordinates representations

I cannot really get into this without talking about coordinate representations of points on the elliptic curves. There are different representations that admit different algorithms, and that is a bummmer. The biggest issue we'll come across are addition and doubling of points on curves, and these will be better or worse depending on which coordinate system we use. That being said, here is an overview of the different options that we will consider:

- Affine
    - this is the most basic and intuitive, it is simply the pair of coordinates $(x,y)$ such that the pair represents a point that lies on the curve, aka $y^2=x^3+3$. 
    - Not favourable for doubling or addition because it involves inversion, which for a prime field with order as large as ours, is the most extremely ineffecient of the arithmetic operations on elliptic curves. 
- projective
    - this coordinate system solves the problem of inversion by the introduction of a third element that replaces inversion with a few other operations that are cheaper
        - they are therefore defined by a tuple $[X : Y : Z]$
    - the conversion from affine to projective is simply $\texttt{proj}: \mathbb{F}_p\times\mathbb{F}_p\to\mathbb{F}\mathbb{P}\times\mathbb{F}\mathbb{P}; (x,y)\to [X=x : Y=y : Z=1]$
        - points of the form $[X : Y : 0]$ are the point(s) of infinity 
- Jacobian
    - this is a special subset of projective coordinates where $(x,y) = (X/Z^2, Y/Z^3)$
    - this seems to admit very efficient operations on coordinates, specifically for addition and doubling
- extended twisted coordinates
    - this introduces a fourth variable that now unifies the addition and doubling formulae, are De Smet et al shows that this can be parallelized

We'll deal with Jacobian coordinates in the entirety of what follows, since that's where the good stuff seems to be.


### Modular multiplication

Can't really be parallelized as far as I found. Fastest algorithm that exists is the Montgomery reduction algorithm, which is outlined as Algorithm 14.32 in [the handbook](https://cacr.uwaterloo.ca/hac/about/chap14.pdf), and is optimized for word-by-word reduction! very sweet. The algorithm is faster at the expense of a precomputation step of the parameter $\texttt{inv}=(-q^{-1}mod 2^64)mod 2^64$, but this is easy to do since the parameter is constant for every element in the field. The algorithm is given below, and an example toy implementation is given in my `Scalar` class in `bls.ipynb`, which is untested and unoptimized. An excellent implementation already exists in [alloy](https://docs.rs/ruint/1.12.3/src/ruint/algorithms/mul_redc.rs.html#7), so let's use it! Note that this is for the multiplication of 2 256-bit (in our case) numbers, which is independent of the coordinate representation. This is just a fast modular multiplication algorithm so it's general enough to include in our implementation regardless of the choice of affine vs jacobian.

#### Listing 1: Montgomery multiplication

**INPUT**: integers $m = (m_{n-1} \cdots m_1 m_0)_b$, $x = (x_{n-1} \cdots x_1 x_0)_b$, $y = (y_{n-1} \cdots y_1 y_0)_b$
with $0 \leq x, y < m$, $R = b^n$ with $\gcd(m, b) = 1$, and $m' = -m^{-1} \bmod b$.

**OUTPUT**: $xyR^{-1} \bmod m$.

1. $A \leftarrow 0$. (Notation: $A = (a_n a_{n-1} \cdots a_1 a_0)_b$.)
2. For $i$ from $0$ to $(n - 1)$ do the following:

   i.  $u_i \leftarrow (a_0 + x_i y_0)m' \bmod b$.

   ii. $A \leftarrow (A + x_i y + u_i m)/b$.
   
3. If $A \geq m$ then $A \leftarrow A - m$.
4. Return($A$).
 


### Modular addition and doubling

This is slow in the affine representation because of the inversion, done with either extended euclidean algorithm or modular exponentiation. 

$$
\begin{align*}
\text{Addition:} \quad (x_3, y_3) &= \left(\left(\frac{y_2 - y_1}{x_2 - x_1}\right)^2 - x_1 - x_2, \left(\frac{y_2 - y_1}{x_2 - x_1}\right)(x_1 - x_3) - y_1\right) \\[10pt]
\text{Doubling:} \quad (x_3, y_3) &= \left(\left(\frac{3x_1^2 + a}{2y_1}\right)^2 - 2x_1, \left(\frac{3x_1^2 + a}{2y_1}\right)(x_1 - x_3) - y_1\right)
\end{align*}
$$

This can be improved and even [parallelized](https://doi.org/10.3390/s24031030) if we move to extended twisted edwards coordinates because it removes the branching due to the unity of the addition and doubling formulae, which is why this is called the snark-friendly representation:
$$
(x_3, y_3) = \left(\frac{x_1y_2 + y_1x_2}{1 + dx_1x_2y_1y_2}, \frac{y_1y_2 - ax_1x_2}{1 - dx_1x_2y_1y_2}\right)
$$

But this is a bit much. I recommend all operations on elements on curves be done in projective coordinates, since there are many optimized algorithms for this [outlined here](https://eprint.iacr.org/2015/1060.pdf). 

There's also a good reference for the modular arithmetic within different fields [here](https://eprint.iacr.org/2022/367.pdf). 

