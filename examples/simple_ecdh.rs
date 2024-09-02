use rand::thread_rng;
use sylow::{FieldExtensionTrait, Fp, Fr, G1Projective, GroupTrait};

struct ECDHParty {
    private_key: Fr,
    public_key: G1Projective,
}

impl ECDHParty {
    fn new() -> Self {
        let mut rng = thread_rng();
        let private_key = Fr::rand(&mut rng);
        let public_key = G1Projective::generator() * Fp::from(private_key);

        ECDHParty {
            private_key,
            public_key,
        }
    }

    fn compute_shared_secret(&self, other_public_key: &G1Projective) -> G1Projective {
        *other_public_key * Fp::from(self.private_key)
    }
}

fn main() {
    // Alice generates her key pair
    let alice = ECDHParty::new();
    println!("Alice's public key: {:?}", alice.public_key);

    // Bob generates his key pair
    let bob = ECDHParty::new();
    println!("Bob's public key: {:?}", bob.public_key);

    // Alice computes the shared secret
    let alice_shared_secret = alice.compute_shared_secret(&bob.public_key);
    println!("Alice's computed shared secret: {:?}", alice_shared_secret);

    // Bob computes the shared secret
    let bob_shared_secret = bob.compute_shared_secret(&alice.public_key);
    println!("Bob's computed shared secret: {:?}", bob_shared_secret);

    // Verify that both parties computed the same shared secret
    assert_eq!(alice_shared_secret, bob_shared_secret);
    println!("ECDH key exchange successful!");
}
