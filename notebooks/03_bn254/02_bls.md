---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.16.3
  kernelspec:
    display_name: Rust
    language: rust
    name: rust
---

<!-- #region -->
## BN254 with Thresholding

We want to be able to perform signature verification on a hashed message. However, if we only have a single entity producing a signature, we require trust that they are honest, which is a hard requirement since they are indivudually responsible for the integrity of the signature. To circumvent this, we produce a *threshold* signature scheme, specifically what is known as a $(t,n)$-thresholding scheme. This means that out of a council of $n$ participants, any quorum of $t$ valid partial signatures guarantees validity of the final signature. This allows for a decentralized signaturing, fault tolerance, and validation and verification of and by participants. 

### Signature schemes

There are a few signatures schemes. I will mention by name, but not go into the details. There are many schemes that produce many valid signatures (DSA, ECDSA, Schnorr), but we want a single valid signature. We therefore start with the Boneh-Lynn-Shacham (BLS) signature scheme, which is pretty ubiquitous. 

#### Key generation

First choose $x\sim U(0, p)\in\mathbb{F}_p$ to be the random key, the holder of which generates a public key $g^x$ with $g$ a generator of $\mathbb{F}_p$. 

#### Signing

Given a message $m$, hash it to the target group to produce $H(m)$, and return a signature on the hash $\sigma = xH(m)$

#### Verificiation

Assert that $e(\sigma, g)=e(H(m), g^x)$, where $e$ is a pairing function. 

We discuss all of these in detail, as well as the extension to distributed usage among $n$ participants.

### Contents
[Step 0: Roadmap](#Step-0:-Roadmap)

[Step 1: Generate field scalars](#Step-1:-generate-field-scalars)

[Step 2: Generate partial private shares](#Step-2:-generate-partial-private-shares)

[Step 3: Create public polynomial](#Step-3:-create-public-polynomial)

[Step 4: partial signaturing](#Step-4:-partial-signaturing)

[Step 5: partial verification](#Step-5:-partial-verification)

[Step 6: aggregation](#Step-6:-aggregation)

[Step 7: final verify](#Step-7:-final-verify)

### tl;dr


There are a lot of good partial implementations of everything in this document. my recommendation is to start with [seda's barebones of bn254](https://github.com/sedaprotocol/bn254) and the [pairing library here](https://github.com/paritytech/bn) to create our skeleton. These two libraries have minimal external dependencies, and are lightwight renditions of the functionality. We then take the thresholding logic of [threshold_bls](https://github.com/ARPA-Network/BLS-TSS-Network/tree/75da9ae432516002b12e37b16b4a4b3568c79529/crates/threshold-bls) for the  partial signature generation and aggregation, etc. (all of its curve logic is imported from external crates so I don't recommend starting off with this).

The biggest issue in these existing repos is the security concerns regarding the `hash_to_field` and `field_to_curve` functions, which are only implemented with naïve algorithms in these repos. Fortunately, there is a clear guide to developing secure elliptic curve suites created by cloudflare called [RFC 9380](https://datatracker.ietf.org/doc/html/rfc9380) which specifies very clearly, with example algorithms, references, and precise language, how to remedy these issues, and what algorithms to use for which curves, security levels, etc.

There are implementations by [arkworks](https://github.com/arkworks-rs/algebra/tree/master/curves/bn254) and [zkcrypto/bls12_381](https://github.com/zkcrypto/bls12_381/tree/main). Arkworks unfortunately is extermely bloated and very massive for something that only provides the elliptic curve logic, and zkcrpto/bls12_381 is the wrong curve. However,  arkworks is a good reference for our friendly bn254, and zkcrypto/bls12_381 conforms to security standards set out in RFC9380, so they should be good references while we build our product.

    
### Step 0: Roadmap 

For the BN254 curve, there are two groups we will deal with often.

##### $\mathbb{G}_1\subset\mathrm{E}(\mathbb{F}_r)$ with $\rm E$ the curve

- This is the group of points on the base curve in short Weierstrass form $y^2=x^3+3$ defined over the field $\mathbb{F}_r$

##### $\mathbb{G}_2\subset\mathrm{E}^\prime(\mathbb{F}_{r^2})$ with $\rm E^\prime$ the sextic twist of the curve

- This is the group of points on the twisted curve defined over the quadratic extension field $\mathbb{F}_{r^2}$, defined by $y^2=x^3+\frac{3}{i+9}$

---

1. Generate scalars $\{a_0,\ldots,a_{t-1}\}$ in the field $\mathbb{F}_r$
    a. These define private key polynomial coefficients
2. Generate partial key shares by evaluating the polynomial for $n$ shares, making sure to never evalaute at 0
    a. This creates partial priate keys $s_i\in\mathbb{F}_r$
3. Commit the private polynomial to $\mathbb{G}_2$ to create the public key polynomial
    a. Define $A:\mathbb{F}_r\to\mathbb{G}_2:x\to xg_2$, and apply to polynomial, namely $a_i\to A(a_i)=a_ig_2$
    b. The group public key is the evalution of the public key polynomial at $0\in\mathbb{F}_r$, namely $a_0g_2$
4. Each node $i$ will now create a partial signature
    a. First, hash message $m$ into $\mathbb{F}_r$ 
    b. Second, take the hash and map it to the curve, generating $H(m)\in\mathbb{G}_1$
    c. Thirdly, create the partial signature by multiplying by the partial key share $s_i\in\mathbb{F}_r$ by the hash, $\sigma_i=s_iH(m)\in\mathbb{G}_1$
    
5. Verify the partial signatures against the public polynomial
    a. Now having the hash on the curve $H(m)$, and the partial signature $\sigma_i$, we first evaluate the public polynomial $P(x) = a_0g_2 + a_1g_2x+\cdots+a_{t-1}g_2x^{t-1}$ at each index $i$
    b. We then use the pairing function to verify $e(\sigma_i, g_2)=e(H(m), P(i))$ 
    
6. Aggregate the participants and their partial signatures to recover the public polynomial constant term, aka pub key $a_0g_2$, via generation of total signature $\sigma$

7. Use same methodology as step 5 to verify the final signature $e(\sigma, g_2)=\prod_i e(H(m),P(i) )$
<!-- #endregion -->

### Step 1: generate field scalars

#### Listing 1: Generate $s\in\mathbb{F}_r$

```rust 
use rand::Rng;

#[derive(Debug, Clone, Copy)]
pub struct Scalar([u64; 4]);

impl Scalar {
    // The modulus q of BN254 curve
    const MODULUS: [u64; 4] = [
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ];

    // R^2 mod q (used for conversion to Montgomery form)
    const R2: [u64; 4] = [
        0x1bb8e645ae216da7,
        0x53fe3ab1e35c59e3,
        0x8c49833d53bb8085,
        0x0216d0b17f4e44a5,
    ];

    // Generate a random Scalar
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut limbs = [0u64; 4];
        
        loop {
            for i in 0..4 {
                limbs[i] = rng.gen();
            }
            
            // Ensure the generated number is less than the modulus
            if !Self::is_above_modulus(&limbs) {
                break;
            }
        }

        // Convert to Montgomery form
        Self::to_montgomery_form(&limbs)
    }

    // Check if the generated number is above or equal to the modulus
    fn is_above_modulus(limbs: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if limbs[i] > Self::MODULUS[i] {
                return true;
            }
            if limbs[i] < Self::MODULUS[i] {
                return false;
            }
        }
        true
    }

    // Convert to Montgomery form
    fn to_montgomery_form(limbs: &[u64; 4]) -> Self {
        let mut result = [0u64; 4];
        Self::montgomery_multiply(limbs, &Self::R2, &mut result);
        Scalar(result)
    }

    // Montgomery multiplication
    fn montgomery_multiply(a: &[u64; 4], b: &[u64; 4], result: &mut [u64; 4]) {
        let mut t = [0u64; 8];

        // Multiply
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let mut product = (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + (carry as u128);
                t[i + j] = product as u64;
                carry = (product >> 64) as u64;
            }
            t[i + 4] = carry;
        }

        // Reduce
        let mut carry = 0u64;
        for i in 0..4 {
            //rando num below is INV=(-q^{-1}mod 2^64)mod 2^64
            //its giving fast inv square root vibes
            let k = t[i].wrapping_mul(0xac96341c4ffffffb);
            let mut sum = (t[i] as u128) + (k as u128) * (Self::MODULUS[0] as u128) + (carry as u128);
            carry = (sum >> 64) as u64;
            for j in 1..4 {
                sum = (t[i + j] as u128) + (k as u128) * (Self::MODULUS[j] as u128) + (carry as u128);
                t[i + j - 1] = sum as u64;
                carry = (sum >> 64) as u64;
            }
            t[i + 3] = carry;
            carry = 0;
        }

        result.copy_from_slice(&t[4..8]);

        // Final reduction
        if Self::is_above_modulus(result) {
            let mut borrow = 0i64;
            for i in 0..4 {
                let diff = (result[i] as i128) - (Self::MODULUS[i] as i128) - (borrow as i128);
                result[i] = diff as u64;
                borrow = if diff < 0 { -1 } else { 0 };
            }
        }
    }
}
```

Many implementations exist. Best ones so far I've found that could add rto the barebones scalar above have montgomery arithmetic added. Consider  [this](https://github.com/arkworks-rs/algebra/blob/5a781ae69c373e46c8d738d147a764a8ee510865/ff/src/fields/models/fp/montgomery_backend.rs#L392) and [that](https://github.com/zkcrypto/bls12_381/blob/4df45188913e9d66ef36ae12825865347eed4e1b/src/scalar.rs#L554).


### Step 2: generate partial private shares

#### Listing 2: evaluate private polynomial at each index

```rust 
#[derive(Debug, Clone, Serialze, Deserialize)]
pub struct Eval<A> {
    pub idx: u32;
    pub val: A
}
let (n, t) = (10, 6);
let coeffs: Vec<Scalar> = (0..t).map(|_|Scalar::random()).collect();

//eval polynomial f(i), but never for i=0 since that exposes the secret
let private_shares = (0..n).map(|i| {
    coeffs.iter().rev().fold(Scalar::zero(), |mut sum, coeff| {
        sum.mul(i+1);
        sum.add(coeff);
        Eval<Scalar> {
            idx: i+1,
            value: sum
        }
    }
}).collect::<Vec<_>>();
//put in eval struct or something for clarity / serialization later
```

Great. Now we have evaluated the polynomial $f(x) = a_0 +a_1x+\cdots+a_{t-1}x^{t-1}$. Now we get to the fun stuff 

### Step 3: create public polynomial

First, we need to commit the scalar polynomial generated above to the group to get polynomial on the group, aka multiply each coeff by the generator. We call it committing because of the close connection to [KZG polynomials](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf) in SNARKS (a good blog on it is [here](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html)). 

all of arkworks-rs, zkcrypto/bls12_381, an threshold_bls implement a struct specifically mapping a Scalar of the field to point on $\mathbb{G}_2$

```rust 
let public_polynomial_g2_coeffs = coeffs.iter().map(|c|{
    let mut commit = <cofactor of G2>;
    commit.mul(c);
    commit
}).collect::<Vec<<stuct of points on the field>>>();
```

then BAM, we get the public key for "free" since its just the constant term of the polynomial

```rust 
let pub_key:<stuct of points on the field> = public_polynomial_g2_coeffs[0];
```

We place the public key as an element of G2. Why?
- prevents rogue key attacks, since more complex structure makes it harder to generate fake pub keys
- subgroup structure is more complex, so harder to cofactor clear
- allows for optimizations in the pairing equation

Also, note that in order to get an element of G2 we multiply by the cofactor, see [membership checks](#Membership-checks). The problem is really that this cofactor is huge:

```rust
//|E'(F_{p^2})| = 
//479095176016622842441988045216678740799252316531100822
//436447802254070093686356349204969212544220033486413271
//283566945264650845755880805213916963058350733
c_2 = 21888242871839275222246405745257275088844257914179612981679871602714643921549
```

so there are [faster ways to generate an element in G2](https://datatracker.ietf.org/doc/html/rfc9380#name-clearing-the-cofactor), for example [this](https://eprint.iacr.org/2017/419.pdf). 
### Step 4: partial signaturing
ok, great. c'est parti à la lune . we now need to partial sign messages. this is distributed obvs in our case, but for here it'd be nice to have something like

```rust 
let partials_sigs_g1 = private_shares.iter().map(|s| bn254::partial_sign(s, &msg));
```

<!-- #region -->
but what does this actually entail? this is the good stuff. 

##### Choose an upper bound on the target security level $k$, a reasonable choice of which is $\lceil\log_2(r)/2\rceil$

##### Define a hash_to_field function to take byte strings to field

From RFC 9380, 
>To control bias, hash_to_field instead uses random integers whose length is at least $\lceil \log_2(p)\rceil + k$ bits, where k is the target security level for the suite in bits. Reducing such integers mod p gives bias at most 2^-k for any p; this bias is appropriate when targeting k-bit security. For each such integer, hash_to_field uses expand_message to obtain L uniform bytes, where $L = \lceil(\lceil\log_2(p)\rceil + k) / 8\rceil$. These uniform bytes are then interpreted as an integer via OS2IP. For example, for a 255-bit prime p, and k = 128-bit security, L = ceil((255 + 128) / 8) = 48 bytes.

More on this later.


##### Define a field_to_curve function to take field element to $\mathbb{G}_1$


---

First, we need a way to take a message and hash it to an element of the field, so we use ...

#### Listing 3: "try and increment" algorithm for hashing onto $\mathbb{Z}_n$

<blockquote>
Require: n $\in$ Z with |n|_2 = k and s $\in$ {0,1}*
    
$\quad$ procedure Try-and-Increment(n, k, s)

$\qquad$    c ← 0

$\qquad$   repeat

$\qquad\quad$       s' ← s || c_bits()

$\qquad\quad$        z ← H(s')_0 · 2^0 + H(s')_1 · 2^1 + ... + H(s')_k · 2^k

 $\qquad\quad$       c ← c + 1
 
 $\qquad$   until z < n
 
 $\qquad$   return z
 
$\quad$ end procedure

Ensure: z $\in$ Z_n
</blockquote>
     
possible impl [here](https://github.com/ARPA-Network/BLS-TSS-Network/blob/75da9ae432516002b12e37b16b4a4b3568c79529/crates/threshold-bls/src/hash/try_and_increment.rs)

tl;dr $\texttt{try-and-increment}:\{0,1\}^*\to\mathbb{Z}_r;m_2\to m_{\mathbb{Z}_r}\simeq m_{\mathbb{F}_r}$, which is what is given in moon math manual.

This seems easy enough, but would fail security audits. We should implement a more rigorous method for a given level of security, which for us is 128-bit. An example might be `expand_message_xmd` specified again by RFC 9380, an example impl of which could be:

#### Listing 4: expand_message_xmd for hash_to_field

<!-- #endregion -->

```rust 
use sha2::{Sha256, Digest};
use num_bigint::BigUint;
use num_traits::Num;

const B_IN_BYTES: usize = 32; // 256 bits for SHA-256
const S_IN_BYTES: usize = 64; // Input block size for SHA-256
const L: usize = 48; // ceil((254 + 128) / 8) = 48 bytes

const P: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES;
    
    assert!(ell <= 255, "ell is too large");
    assert!(len_in_bytes <= 65535, "len_in_bytes is too large");
    assert!(dst.len() <= 255, "DST is too long");

    let dst_prime: Vec<u8> = [dst, &(dst.len() as u8).to_be_bytes()].concat();
    let z_pad = vec![0u8; S_IN_BYTES];
    let l_i_b_str = (len_in_bytes as u16).to_be_bytes();

    let msg_prime: Vec<u8> = [
        &z_pad[..],
        msg,
        &l_i_b_str,
        &[0u8],
        &dst_prime[..]
    ].concat();

    let mut b_0 = Sha256::digest(&msg_prime);
    let mut b_1 = Sha256::digest(&[&b_0[..], &[1u8], &dst_prime[..]].concat());

    let mut uniform_bytes = b_1.to_vec();

    for i in 2..=ell {
        let b_i = Sha256::digest(
            &[
                &xor(&b_0, &b_1)[..],
                &[i as u8],
                &dst_prime[..]
            ].concat()
        );
        uniform_bytes.extend_from_slice(&b_i);
        b_1 = b_i;
    }

    uniform_bytes.truncate(len_in_bytes);
    uniform_bytes
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

fn i2osp(x: usize, len: usize) -> Vec<u8> {
    x.to_be_bytes()[std::mem::size_of::<usize>() - len..].to_vec()
}

fn hash_to_field(msg: &[u8], dst: &[u8]) -> BigUint {
    let uniform_bytes = expand_message_xmd(msg, dst, L);
    let mut integer = BigUint::from_bytes_be(&uniform_bytes);
    let p = BigUint::from_str_radix(P, 10).unwrap();
    integer %= &p;
    integer
}
```

<!-- #region -->

---

Now having the message in the field, we need to map it to $\mathbb{G}_1$, aka a pair of $(x,y)\in \rm E(\mathbb{F}_r)$


It seems the nicest would be the Simplified Shallue-van de Woestijne method. I won't waste time on this one unfortunately, because despite there being an existing impl of [this](https://github.com/zkcrypto/bls12_381/blob/4df45188913e9d66ef36ae12825865347eed4e1b/src/hash_to_curve/map_g2.rs#L388), it requires that in its short affine Weierstrass form that $A\neq 0$ and $B\neq 0$, so we instead present the full ...

##### Shallue-van de Woestrijne method

Needed constants: 
- A=0, B=3 for bn254 
- $Z\in\mathbb{F}_r$ such that
  - for $y^2=g(x)=x^3+Ax+B$, $g(Z)\neq 0$ in the field
  - $-\frac{3Z^2+4A}{4g(Z)}\neq 0$ in the field
      - ALSO this quantity must be a square in the field
  - At least one of $g(Z)$ and $g(-Z/2)$ is square in the field

#### Listing 5: A sage script to find such a $Z$
<!-- #endregion -->

```rust 
# Arguments:
# - F, a field object, e.g., F = GF(2^521 - 1)
# - A and B, the coefficients of the curve y^2 = x^3 + A * x + B
def find_z_svdw(F, A, B, init_ctr=1):
    g = lambda x: F(x)^3 + F(A) * F(x) + F(B)
    h = lambda Z: -(F(3) * Z^2 + F(4) * A) / (F(4) * g(Z))
    # NOTE: if init_ctr=1 fails to find Z, try setting it to F.gen()
    ctr = init_ctr
    while True:
        for Z_cand in (F(ctr), F(-ctr)):
            # Criterion 1:
            #   g(Z) != 0 in F.
            if g(Z_cand) == F(0):
                continue
            # Criterion 2:
            #   -(3 * Z^2 + 4 * A) / (4 * g(Z)) != 0 in F.
            if h(Z_cand) == F(0):
                continue
            # Criterion 3:
            #   -(3 * Z^2 + 4 * A) / (4 * g(Z)) is square in F.
            if not is_square(h(Z_cand)):
                continue
            # Criterion 4:
            #   At least one of g(Z) and g(-Z / 2) is square in F.
            if is_square(g(Z_cand)) or is_square(g(-Z_cand / F(2))):
                return Z_cand
        ctr += 1
```


LOL all this to show that for BN254, $Z=1\in\mathbb{F}_r$ ...

Using the notation and utility functions from [here](https://datatracker.ietf.org/doc/html/rfc9380#name-utility-functions), I summarise the SvW algorithm for input $u\in\mathbb{F}_r$.

Note that the constant c3 below MUST be chosen such that sgn0(c3) = 0. In other words, if the square-root computation returns a value cx such that sgn0(cx) = 1, set c3 = -cx; otherwise, set c3 = cx.

Constants:
1. $c1 = g(Z)$
2. $c2 = -Z / 2$
3. $c3 = \sqrt{-g(Z) * (3Z^2 + 4A)}$     # sgn0(c3) MUST equal 0
4. $c4 = -4g(Z) / (3Z^2 + 4A)$

#### Listing 6: the SvW algorithm $A:\mathbb{F}_r\to \mathbb{F}_r\times\mathbb{F}_r$

```rust vscode={"languageId": "plaintext"}
tv1 = u^2
 tv1 = tv1 * c1
 tv2 = 1 + tv1
 tv1 = 1 - tv1
 tv3 = tv1 * tv2
 tv3 = inv0(tv3)
 tv4 = u * tv1
 tv4 = tv4 * tv3
 tv4 = tv4 * c3
 x1 = c2 - tv4
gx1 = x1^2
gx1 = gx1 + A
gx1 = gx1 * x1
gx1 = gx1 + B
 e1 = is_square(gx1)
 x2 = c2 + tv4
gx2 = x2^2
gx2 = gx2 + A
gx2 = gx2 * x2
gx2 = gx2 + B
 e2 = is_square(gx2) AND NOT e1   # Avoid short-circuit logic ops
 x3 = tv2^2
 x3 = x3 * tv3
 x3 = x3^2
 x3 = x3 * c4
 x3 = x3 + Z
  x = CMOV(x3, x1, e1)   # x = x1 if gx1 is square, else x = x3
  x = CMOV(x, x2, e2)    # x = x2 if gx2 is square and gx1 is not
 gx = x^2
 gx = gx + A
 gx = gx * x
 gx = gx + B
  y = sqrt(gx)
 e3 = sgn0(u) == sgn0(y)
  y = CMOV(-y, y, e3)       # Select correct sign of y
return (x, y)
```


Then poof! We have the following procedure:

1. **Hashing to element of the field:** use listing 4 to convert the bits of the message to an integer of desired size and field via try-and-increment
    a. `hash_to_field` : $\{0,1\}^*\to\mathbb{F}_r; m_2\to m_{\mathbb{F}_r}$
3. **Hashing element of the field to the curve:** use listings 5-6 to then map hashed message to the curve!
    a. `field_to_curve` : $\mathbb{F}_r\to\mathbb{G}_1; m_{\mathbb{F}_r}\to H(m)$
5. **Signing of the hash:** now, take the hash and sign it with the partial private key of this node
    a. $\sigma_i: \mathbb{G}_1\to\mathbb{G}_1; H(m)\to s_iH(m)$ with $s_i$ the partial private key $\in\mathbb{F}_r$ from step 2
    
Each participant has now signed the hashed message to the curve.

### Step 5: partial verification

This is pretty straightforward up to deciding how to implement the pairing function.... which is ... easy ... right? Wrong. See 'Field extentions' for the clusterfuck that is pairing maths.

```rust 
let public_polynomial_per_share = (0..n).map(|i| {
    public_polynomial_g2_coeffs.iter().rev().fold(Scalar::zero(), |mut sum, coeff| {
        sum.mul(i+1);
        sum.add(coeff);
        Eval<Scalar> {
            idx: i+1,
            value: sum
        }
    }
}).collect::<Vec<_>>(); //these are the values of public poly we'll use for verification
let all_verified = (0..n).map(|i|{
        let lhs = pairing(partials_sigs_g1[i], <generator of g_2>);
        let rhs = pairing(<hash to be saved from previous calculation>, public_polynomial_per_share[i])
        lhs == rhs
    }).sum() == n - 1;
```


### Step 6: Aggregation
First, get lagrange coeffs $\lambda_i$ to recombine the partial signatures

```rust 
fn lagrange_coefficient(i: usize, indices: &[usize]) -> Scalar {
    let x_i = Scalar::from(i as u64);
    indices.iter().filter(|&&j| j != i).fold(Scalar::one(), |acc, &j| {
        let x_j = Scalar::from(j as u64);
        acc * (x_j * (x_j - x_i).inverse().unwrap())
    })
}
```

Then, we can aggregate the signatures to create $\sigma=\sum_i\lambda_i\sigma_i$


```rust 
fn aggregate_signatures(partial_sigs: &[(usize, <point in G1>)]) -> <point in G1> {
    let indices: Vec<usize> = partial_sigs.iter().map(|&(i, _)| i).collect();
    
    partial_sigs.iter().map(|&(i, sig)| {
        let lambda_i = lagrange_coefficient(i, &indices);
        sig.mul(lambda_i)
    }).sum()
}
```

In reality we don't need all partials (handle edge cases, plus verify each partial individual first for data integrity, etc)

### Step 7: Final verify

Use same code as step 5 to verify the final signature $\sigma$. 
