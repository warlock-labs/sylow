## optimal ate pairing

finally, we're here!! fuck.

There are many choices here, and I'm only choosing one (the "best" one), but the motivation for this I won't go into here. There is a great outline of the many types of pairings [here](https://eprint.iacr.org/2008/096.pdf), in one of the orignal manuscripts on the subject.

So our goal here is to take a point $X\in\mathbb{G}_1= E(\mathbb{F}_p)$, and a point $Y\in\mathbb{G}_2\subset E^\prime(\mathbb{F}_{p^{12}})$, and map them to a point in a target group $\mathbb{G}_T\subset\mathbb{F}_{p^{12}}$, denoted by the map $e$, and corresponds qualitatively to multiplying a point in $\mathbb{G}_1$ by a point in $\mathbb{G}_2$. 

We need bilinearity, therefore requiring:
$$
e([a]X, [b]Y) = e(X, [b]Y)^a = e(X, Y)^{ab} = e(X, [a]Y)^b = e([b]X, [a]Y)
$$

The "best" way to create this $e$ is the "optimal ate pairing", which has an *excellent* guide for [high speed calculations in software](https://eprint.iacr.org/2010/354.pdf).

Before we dig into the pairing itself, we need to know how to define a line passing through two points on the twisted curve, and what the line is evaluated at a point on the curve. Specifcally, $R_1=(x^\prime_1, y^\prime_1), R_2=(x^\prime_2, y^\prime_2)\in E^\prime(\mathbb{F}_{p^2})$, and $T=(x,y)\in E(\mathbb{F}_p)$, we have the line $\ell$ defined as:

$$ 
\ell_{\Psi(R_1),\Psi(R_2)}(T) = \begin{cases}
w^2 (x^\prime_2-x^\prime_1)y + w^3(y^\prime_1-y^\prime_2)x + w^5(x^\prime_1 y^\prime_2-x^\prime_2 y^\prime_1) & R_1\neq R_2\\
(3x^{\prime 3}-2y^{\prime 2})(9+u) + w^3(2yy^\prime) + w^4(-3xx^{\prime 2})               & R_1=R_2
\end{cases}
$$

Armed with this knowledge, we now can define the optimal ate pairing $e:\mathbb{G}_1\times\mathbb{G}_2\to\mathbb{G}_T$ to be:

\begin{align}
e(X, Y) =\bigg(&f_{6z+2,Y}(X)\\
\times &\ell_{[6z+2]\Psi(Y),\phi_p(\Psi(Y))}(X)\\
\times &\ell_{[6z+2]\Psi(Y)+\phi_p(\Psi(Y)), -\phi_p(\Psi(Y))}(X)\bigg)^{\frac{p^{12}-1}{r}}
\end{align}

now THATS a mouthful, say that 5 times fast. Here, $z$ is the parameter of the curve. The pairing is based on rational functions $f_{i,Q}:\mathbb{N}\times\mathbb{G}_2\to\mathbb{F}_{p^{12}}$ that are evaluated iteratively in what's called Miller's algorithm. 

Fantastically, the [paper](https://crypto.stanford.edu/miller/miller.pdf) that describes this process was never published, but the algorithm, the imeplementation of which is refered to as "Miller's loops", says that:

$$
f_{i+j,Y} = f_{i,Y}f_{j,Y}\ell_{[i]\Psi(Y),[j]\Psi(Y)}
$$

TECHNICALLY there is another factor in the denominator of these iterations that describes the evaluation of the point $\Psi(Y)$ on the vertical line passing through $X$. However, we can ignore this evaluation, for reasons summarized well by [this](https://crypto.stanford.edu/pbc/notes/ep/optimize.html):

<blockquote>

To compute a Tate pairing, a quotient is iteratively calculated (Miller’s algorithm) and then raised to power of $(p^k-1)/r$, the Tate exponent. Each factor of the denominator is the equation of a vertical line evaluated at a particular point, i.e. the equation $X-a$ evaluated at some point $(x,y)$, which gives the factor $(x-a)$. 

Because of the way we have selected our groups, $x\in\mathbb{F}_{p^d}$, (note that the map $\Psi$ leaves the $x$-coordinate of its input in the same field), and $a\in\mathbb{F}_p$, hence $(x-a)\in\mathbb{F}_{p^d}$. 

Any element $a\in\mathbb{F}_{p^d}$ satisfies $a^{p^d-1}$. Observe $p^d-1$ divides $(p^k-1)/r$, because $r$ cannot divide $p^d-1$ (otherwise $d$ would be the embedding degree, not $k$). Thus each factor $(x-a)$ raised to the Tate exponent is 1, so it can be left out of the quotient. Hence, there is no need to compute the denominator at any time in Miller's algorithm.

</blockquote>

Slick.

### Toy implementation

In decimals, we know $z=4965661367192848881$, and therefore $6z+2=29793968203157093288$. Optimised implementations represent this bound in $\{-1, 0, 1\}$ basis, not binary, since it has a lower Hamming weight, just fyi, so in that case we get the following.

There will be miller's loop to determine the first term in the optimal ate pairing. Then for the final two terms, we notice that:

##### $\ell_{[6z+2]\Psi(Y),\phi_p(\Psi(Y))}(X)$

Notice that: 
$$
    \phi_p(\Psi(Y)) = \left((w^2 x^\prime)^p, (w^3y^\prime)^p\right)= \left(w^2\xi^{(p-1)/3}x^{\prime p}, w^3\xi^{(p-1)/2}y^{\prime p}\right) = \Psi\left(\xi^{(p-1)/3}\bar{x}^\prime, \xi^{(p-1)/2}\bar{y}^\prime\right)
$$
Since $[n]\Psi(Q)=\Psi([n]Q)$ by the homomorphism, we just evaluate the line now at the point $Q^\prime = (\xi^{(p-1)/3}\bar{x}^\prime, \xi^{(p-1)/2}\bar{y}^\prime)=(x_1, y_1)$.
    
##### $\ell_{[6z+2]\Psi(Y)+\phi_p(\Psi(Y)), -\phi_p(\Psi(Y))}(X)$

You can likewise show that this is easily evaluated at the point $-Q$.


```python 
fn e(p: &G1Affine, q: &G2Affine) -> Fq12 {
    //membership checks, see sections above
    assert!(p.is_in_g1());
    assert!(q.is_in_g2());
    
    if p.is_identity().into() || q.is_identity.into() {
        return Fq12::One();
    }
    
    let mut r = *q;
    let mut f = Fq12::One(); //starting point of iteration
    
    //begin miller's loop, calculating f_{[6z+2],q}(p)
    for i in (0..BOUND.len() - 1).rev() {
        f = f * f * line(twist(&r), twist(&r), p);
        r = r.double();
        match BOUND[i] {
            1 => {
                f = f * line(untwist(&r), untwist(q), p);
                r.add_assign(q);
            },
            -1 => {
                f = f * line(untwist(&r),untwist(-q), p);
                r.sub_assign(q);
            },
            0 => {},
            _ => panic!("digit not in correct basis")
        }
    }
    let qp = q.frobenius_map();
    f = f * line(twist(&r), twist(&qp), p);
    r.add_assign(qp);
    let qpp = -qp.frobenius_map();
    f = f* line(twist(&r), twist(&qpp), p);
    
    final_exponentiation(&f)
}
```

## Final exponentiation

Arguably, this is the most computationally expensive step since the bit size of the exponent in the pairing is huge, so the naïve approach would be silly. I mean, there are issues with the $\mathbb{G}_2$ cofactor clearing to create elements in $\mathbb{G}_2$ from the field because of the size of the cofactor, so if multiplication is slow, exponentiation is not guaranteed to be better *a priori*. 

The following takes the lead from [this](https://eprint.iacr.org/2020/875.pdf) and [that](https://eprint.iacr.org/2008/490.pdf). 

The most efficient calculation of these pairings relies on notions of *cyclotomic subgroups*. oof. 

Up until this point, we were precise in our definitions of $\mathbb{G}_1$ and $\mathbb{G}_2$, but have been unclear about what exactly the target group of the pairing should be. We now formally define the target group $\mathbb{G}_T$ to be the group of $r$-th roots of unity over the multipicative group $\mathbb{F}_{p^k}^\ast=(\mathbb{F}_{p^k}/ \{0\}, \ast)$, denoted commonly by $\mu_r$. Why the roots o f unity? Great question. Remember that this mapping has to satisfy a few key real-world properties. First, it has to be a trapdoor, namely preimage resistance (assuming DL hardness), and mapping backwards from the roots of unity is a very difficult problem. Second, it allows for an easy metric against which we can compare two mappings. For example, in the case of signature verification $e(\sigma_i, g_2)=e(H(m), P(i))$, it is very natural to want to set the actual value of each side of this equation to "one", therefore implying the image domain to be the roots of unity. Note that this implies right away that $|\mathbb{G}_1|=|\mathbb{G}_2|=|\mathbb{G}_T|=r$, which makes the pairing retain the correct group structure while still mapping to a cryptographically secure image, aka a group of "ones".

In the following, let $(\mathbb{F}_{p^k}^\ast)^r$ is the subgroup of $r$-th powers, namely all elements in $\mathbb{F}_{p^k}^\ast$ that are expressed as $x^r$ for some $x$. We can then define the quotient group $\mathbb{F}_{p^k}^\ast / (\mathbb{F}_{p^k}^\ast)^r$ which represent the coset of $r$ powers, namely each element in this quotient group differ by a power of $r$. 

Note that $\forall x\in\mathbb{F}_{p^k}^\ast$, $\left(x^{\frac{p^k-1}{r}}\right)^r = x^{p^k-1} = 1$, which means elements of the form $x^{\frac{p^k-1}{r}}\in\mathbb{F}_{p}^\ast / (\mathbb{F}_{p}^\ast)^r$, which is precisely what the pairing function $e$ does. There is a natural isomorphism between the quotient group and the roots of unity, so we can equivalently talk about either. For the purposes of the following, however, we'll keep to the quotient group representation since it admits a few additional insights we can use to our advantage. 

---

Aside: this is not a light topic to cover, even for the level of depth in this document (hard to believe, I know), but is a result from Galois theory and the so called *Kummer theorems*, see [this](https://websites.umich.edu/~asnowden/teaching/2019/776/cft-01.pdf)

---

Since the optimal ate pairing is mapping our "multiplication" of an element from $\mathbb{G}_1$ and an element from $\mathbb{G}_2$ to the group of roots of unity by means of exponentiation of an element from the base field extension $\mathbb{F}_{p^{12}}$, it would be useful to represent our exponent $(p^{12}-1)/r$ in a form closer related to the roots of unity to which we're mapping. To do this, we define what's called the cyclotomic polynomial, defined by an order $n$. This polynomial contains all of the irreducible factors of $x^n-1$ (which defines the roots of unity), and is therefore the polynomial whose roots are the roots of unity. In this sense, this polynomial captures all of the structure of the roots of unity, and because of its irreducibility, we can use it to build other mappings that deal with the group of roots of unity.

Specifically, we define the $k$-th cyclotomic polynomial $\varPhi(x)$ to be:
$$\frac{p^k-1}{\varPhi_k(p)} = \prod_{j\vert k, j\neq k}\Phi_j(p) $$

which allows us to break down the exponent of the "final exponentiation" step. Writing the embedding degree $k=ds$, where $d$ is a positive integer, we can write:

$$ \frac{p^k-1}{r}=\underbrace{\left[(p^s-1)\cdot\frac{\sum_{i=0}^{d-1}p^{is}}{\varPhi_k(p)}\right]}_\text{easy part}\cdot\underbrace{\left[\frac{\varPhi_k(p)}{r}\right]}_\text{hard part}$$

### Easy part

For BN254, this decomposes the easy part into $(p^6-1)(p^2+1)$ for $k=12$ (note that we choose this decomposition because exponentiation by powers of $p$ are very efficient, see the discussion [earlier](#12-th-order-extension-of-the-base-field)). The easy part will involve something like $x^{p^6-1}=x^{p^6}\cdot x^{-1}$, which is one conjugation, one inversion, and one multiplication (remember that conjugation in $\mathbb{F}_{p^{12}}$ for an element $x=a+bw$ is simply $\bar{x}=a-bw$). Then taking $\left(x^{p^6-1}\right)^{p^2}$ is just applying our Frobenius morphism $\phi$, and then finally we multipy by our already-computed value $x^{p^6-1}$, and voila!

Easy part = 1 conjugation + 1 inversion + 1 multiplication + 5 multiplications + 1 multiplication

### Hard part

For BN254, the hard part decomposes into $\frac{p^4-p^2+1}{r}$. It seems that the typical way to go here is to take a base-$p$ expansion, namely defining $\lambda\triangleq m\varphi_k(p)/r$ with $r\nmid m$, and finding a vector $\tau$ of $w+1$ integers $\tau=(\lambda_0,\ldots,\lambda_w)$ such that $\lambda=\sum\lambda_i p^i$ minimizing the L1-norm of $\tau$. Recall that for us:
$$ p(z) = 36z^4 + 36z^3 + 24z^2 + 6z + 1 $$
$$ r(z) = 36z^4 + 36z^3 + 18z^2 + 6z + 1 $$
$$ t(z) = 6z^2+1 $$
so substituting these into the hard part of the polynomial as a function of the curve family generator $z$ yields $\lambda_3 p^3+\lambda_2 p^2 +\lambda_1 p + \lambda_0$ with:
$$ \lambda_3(z) = 1 $$
$$ \lambda_2(z) = 6z^2+1 $$
$$ \lambda_1(z) = -36z^3 -18z^2-12z+1 $$
$$ \lambda_0(z) = -36z^3 - 30z^2-18z -2 $$


We now then compute the hard part as a series of multiplications in terms of powers of the easy part. 

1. Compute $f_\mathrm{easy}^z, (f_\mathrm{easy}^z)^z, (f_\mathrm{easy}^{z^2})^z$
2. Use the Frobenius operator, which has efficient representations in powers 1, 2, and 3 of the prime, to compute $f_\mathrm{easy}^p, f_\mathrm{easy}^{p^2}, f_\mathrm{easy}^{p^3}, (f_\mathrm{easy}^z)^p, (f_\mathrm{easy}^{z^2})^p, (f_\mathrm{easy}^{z^3})^p, (f_\mathrm{easy}^{z^3})^{p^2}$

The evaluation then amounts to:

$$ \underbrace{[f_\mathrm{easy}^p \cdot f_\mathrm{easy}^{p^2} \cdot f_\mathrm{easy}^{p^3}]}_{\equiv y_0} \cdot \underbrace{[1/f_\mathrm{easy}]^2}_{\equiv y_1^2} \cdot \underbrace{[(f_\mathrm{easy}^{z^2})^p]^6}_{\equiv y_2^6} \cdot \underbrace{[1/(f_\mathrm{easy}^z)^p]^{12}}_{\equiv y_3^{12}} \cdot \underbrace{[1/(f_\mathrm{easy}^z \cdot (f_\mathrm{easy}^{z^2})^p)]^{18}}_{\equiv y_4^{18}} \cdot \underbrace{[1/f_\mathrm{easy}^{z^2}]^{30}}_{\equiv y_5^{30}} \cdot
\underbrace{[1/(f_\mathrm{easy}^{z^3} \cdot (f_\mathrm{easy}^{z^3})^p)]^{36}}_{\equiv y_6^{36}}$$

These evaluations have efficient algorithms that have been around [for a long time](https://www.sciencedirect.com/science/article/pii/0196677481900031). We take the vector addition chain approach, which is more or less the equivalent of "flattening" that we also see crop up in the reduction of polynomial constraints in instance-witness definitions of R1CS systems. You can show that the following definitions yield efficient computation of these multiexponentials which we take from [the original manuscript](https://eprint.iacr.org/2008/490.pdf):
$$T_0 \leftarrow (y_6)^2 $$
$$T_0 \leftarrow T_0 \cdot y_4 $$
$$T_0 \leftarrow T_0 \cdot y_5 $$
$$T_1 \leftarrow y_3 \cdot y_5 $$
$$T_1 \leftarrow T_1 \cdot T_0 $$
$$T_0 \leftarrow T_0 \cdot y_2 $$
$$T_1 \leftarrow (T_1)^2 $$
$$T_1 \leftarrow T_1 \cdot T_0 $$
$$T_1 \leftarrow (T_1)^2 $$
$$T_0 \leftarrow T_1 \cdot y_1 $$
$$T_1 \leftarrow T_1 \cdot y_0 $$
$$T_0 \leftarrow (T_0)^2 $$
$$f_\mathrm{hard} \leftarrow T_0 \cdot T_1$$

which is only a few multiplications and squarings! Efficient. There's extensions and [improvements](https://doi.org/10.1007/s12190-018-1167-y), but that's the basic stuff.





## BONUS - glued miller loop and improved signature performance

This is pretty sick. Remember that eventually we want to check the relation $e(\sigma_i, g_2)=e(H(m), P(i) )$ for verification. You could just naively evaluate lhs and rhs and check for equality. Right? Or notice that:

$$ e(\sigma_i, g_2) = e(H(m), P(i)) $$
$$ \implies e(\sigma_i, g_2)e(H(m), P(i))^{-1} = 1$$
$$ \implies e(\sigma_i, g_2)e(H(m), -P(i)) = 1 $$
$$ \implies \left(f_{[6z+2], \sigma_i}(g_2)f_{[6z+2], H(m)}(-P(i))\right)^\frac{p^{12}-1}{r} = 1$$


which results in only having to evaluate a single Miller loop, followed by a single exponentiation at the end! Also during the recursion we don't need to track $f_{i,s}(G)$ nor $f_{i,H(m)}(-xG)$, just their product, which saves a multiplication in $\mathbb{F}_{12}$ in each iteration of this *glued* Miller loop. The savings compound since we're aggregating many partial signatures, and the idea works exactly the same for the aggregated signatures. Namely, verification is equivalent to:

$$ 
\left(\prod_{i}^tf_{[6z+2], \sigma_i}(g_2) f_{[6z+2], H(m)}(-P(i))\right)^\frac{p^{12}-1}{r} = 1
$$

---

This is the jist of it. There's so many more things to work with, like different pairings like the [Xate pairing](https://link.springer.com/chapter/10.1007/978-3-540-85538-5_13), but that's beyond the scope here. I'll just mention maybe that there are many more cleverer things you can do to take full advantage of the cyclotomic subgroup stuff like [efficient compression and arithmetic on compressed representations of elements](https://eprint.iacr.org/2010/542.pdf), but that's over the top for now.
