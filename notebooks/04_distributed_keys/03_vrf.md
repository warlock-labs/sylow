## VRF

The problem with a pseudorandom oracle is that it is, by its construction, NOT verifiable. Namely, without knowledge of the seed $s$, you cannot distinguish the return value of a pseudorandom function $f_s$ from an independently selected random string. This therefore requires trust on behalf of the oracle to produce and faithfully execute the evaluation of the oracle function $f_s(x)$. You could remove trust by publishing the seed, but then you remove all unpredictability.

You can instead use a proof to validate the faithful execution of $f_s(x)$ without actually revealing $s$.
A proof $\sf proof_x$ would say that a unique value $v$ is provable as the value of $f_s(x)$. This is what is called a verifiable random function (VRF).

### Issues with proofs

If we allow interaction, then we can use a ZK proof and a committment scheme of the oracle to the seed $s$. To prove $v=f_s(x)$, the oracle gives a ZK proof to the verifier of the above, and that $c$ is a committement to $s$. But we don't want interaction ideally.

We could move to a noninteracting ZK proof, but this requires consensus on a bit string between prover and verifier that is GUARANTEED to be random. We want to avoid all the ways we coudl generate this random string:

- If the prover chooses the string, this breaks guarantee of the proof and introduces bias
- If the verified chooses the string, the ZK assumption is broken, and the proof system is not guaranteed (namely, the prover could leak info on $s$ and break unpredictability by proof)
- If both jointly choose the string, that's interacting, which we don't want
- If a third party chooses the string, we add a further requirement of trust.

See [here](https://cs.nyu.edu/~dodis/ps/short-vrf.pdf) for more details. 

### Signatures as VRFs

Assume that a scheme exists to generate signatures $\sigma=sH(m)$, with a mapped-to-group hash of a message $m$, and private key $s$. This is unpredictable (by assumption of DL hardness), but verifiable (with knowledge of the pub key and pairing operations on the curve for instance). However:
- There may be many valid signatures for a given string, violating the requirement that elements in the image of the VRF are provably unique
- The signature is unpredictable, not necessary random

The unique provability depends on the actual scheme you use, and you'd hope that your scheme satisfies this, but if your scheme is probabilistic or hysteretic, people have shown that you cannot guaratee unique provability.

These functions are called verifiable unpredictable functions (VUFs).

Is it possible to turn a VUF into a VRF? Yes, and no.

See [here](https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Pseudo%20Randomness/Verifiable_Random_Functions.pdf) for the construction of what this could look like,but this only works IFF $f$ satisfies the property that input lengths are logarithmically related to the security, so in that construction, it suggests that for a BLS signature scheme on BN254 that $|m|=\mathcal{O}(\log L)$, which limits the size of the messages we can securely sign in this approach. So, next!


There are other ways to turn a VUF into VRF, for example hardcore bit extraction. We can use [the following construction](https://dl.acm.org/doi/pdf/10.1145/73007.73010) to replace the oracle function with $f\hookrightarrow f^\prime = \langle f(x),r\rangle_2$, where $r$ is a random binary string and the brackets are inner products. The proof is therefore saying $f^\prime(x)=b$ is a string $v$ such that $\langle r, v\rangle_2=b$ with a proof of $f(x)=v$. This might look like:



```rust
fn hardcore_bit_extraction(signature: &noether::U256)-> Result<noether::U256>{
    let mut rng = rand::thread_rng();
    let rando = noether::U256::from_limbs(rng.gen());
    let mut retval = noether::U256::ZERO;
    for i in 0..256 {
        if (signature.bit(i) ^ rando.bit(i)) == 1 {
            retval = retval.bit_or(noether::U256::ONE.shl(i));
        }
    }
    //add final hash
    let hash = ethers::core::utils::keccak256(retval.to_be_bytes::<32>());
    Ok(noether::U256::from_be_slice(&hash))
}
```