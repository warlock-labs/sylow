use num_traits::{Inv, One, Zero};
use sha3::Keccak256;
use std::collections::HashMap;
use sylow::{
    glued_miller_loop, FieldExtensionTrait, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
    GroupTrait, Gt, XMDExpander,
};

// Constants for the signature scheme
const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
const SECURITY_BITS: u64 = 128;

/// Represents a participant in the threshold signature scheme
#[derive(Clone, Debug)]
struct Participant {
    id: usize,
    secret_key: Fr,
    public_key: G2Projective,
}

/// Represents the threshold signature scheme
struct ThresholdSignature {
    t: usize,
    n: usize,
    participants: Vec<Participant>,
    group_public_key: G2Projective,
}

impl ThresholdSignature {
    /// Creates a new threshold signature scheme
    fn new(t: usize, n: usize) -> Self {
        assert!(
            t <= n,
            "Threshold must be less than or equal to the number of participants"
        );

        let mut rng = rand::thread_rng();
        let secret_polynomial: Vec<Fr> = (0..t).map(|_| Fr::rand(&mut rng)).collect();

        let participants: Vec<Participant> = (1..=n)
            .map(|i| {
                let secret_key = Self::evaluate_polynomial(&secret_polynomial, i);
                let public_key = G2Projective::generator() * Fr::into(secret_key);
                Participant {
                    id: i,
                    secret_key,
                    public_key,
                }
            })
            .collect();

        let group_public_key = G2Projective::generator() * Fr::into(secret_polynomial[0]);

        ThresholdSignature {
            t,
            n,
            participants,
            group_public_key,
        }
    }

    /// Evaluates a polynomial at a given point
    fn evaluate_polynomial(coeffs: &[Fr], x: usize) -> Fr {
        let x = Fr::from(x as u64);
        coeffs
            .iter()
            .rev()
            .fold(Fr::zero(), |acc, coeff| acc * x + *coeff)
    }

    /// Generates a partial signature for a given message and participant
    fn partial_sign(&self, participant_id: usize, message: &[u8]) -> G1Projective {
        let participant = self
            .participants
            .iter()
            .find(|p| p.id == participant_id)
            .expect("Participant not found");

        let expander = XMDExpander::<Keccak256>::new(DST, SECURITY_BITS);
        let hashed_message = G1Projective::hash_to_curve(&expander, message)
            .expect("Failed to hash message to curve");

        hashed_message * Fr::into(participant.secret_key)
    }

    /// Verifies multiple partial signatures at once using the glued Miller loop
    fn batch_verify_partial(
        &self,
        message: &[u8],
        signatures: &HashMap<usize, G1Projective>,
    ) -> bool {
        let expander = XMDExpander::<Keccak256>::new(DST, SECURITY_BITS);
        let hashed_message = G1Projective::hash_to_curve(&expander, message)
            .expect("Failed to hash message to curve");

        let g2_gen = G2Affine::from(G2Projective::generator());
        let mut g1_points = Vec::new();
        let mut g2_points = Vec::new();

        for (&id, signature) in signatures {
            let participant = self
                .participants
                .iter()
                .find(|p| p.id == id)
                .expect("Participant not found");

            g1_points.push(G1Affine::from(*signature));
            g1_points.push(G1Affine::from(-hashed_message));
            g2_points.push(g2_gen);
            g2_points.push(G2Affine::from(participant.public_key));
        }

        let g2_precomp: Vec<_> = g2_points.iter().map(|p| p.precompute()).collect();
        let miller_result = glued_miller_loop(&g2_precomp, &g1_points);
        miller_result.final_exponentiation() == Gt::identity()
    }

    /// Aggregates partial signatures into a full signature
    fn aggregate(&self, partial_signatures: &HashMap<usize, G1Projective>) -> G1Projective {
        assert!(
            partial_signatures.len() >= self.t,
            "Not enough partial signatures"
        );

        let mut aggregated_signature = G1Projective::default();
        let participants: Vec<usize> = partial_signatures.keys().cloned().collect();

        for (&id, signature) in partial_signatures {
            let lambda = self.lagrange_coefficient(id, &participants);
            aggregated_signature = aggregated_signature + (*signature * Fr::into(lambda));
        }

        aggregated_signature
    }

    /// Calculates the Lagrange coefficient for a participant
    fn lagrange_coefficient(&self, i: usize, participants: &[usize]) -> Fr {
        let x_i = Fr::from(i as u64);
        participants
            .iter()
            .filter(|&&j| j != i)
            .fold(Fr::one(), |acc, &j| {
                let x_j = Fr::from(j as u64);
                acc * (x_j * (x_j - x_i).inv())
            })
    }

    /// Verifies the aggregated signature using the glued Miller loop
    fn verify(&self, message: &[u8], signature: &G1Projective) -> bool {
        let expander = XMDExpander::<Keccak256>::new(DST, SECURITY_BITS);
        let hashed_message = G1Projective::hash_to_curve(&expander, message)
            .expect("Failed to hash message to curve");

        let g1_points = [G1Affine::from(*signature), G1Affine::from(-hashed_message)];
        let g2_points = [
            G2Affine::from(G2Projective::generator()),
            G2Affine::from(self.group_public_key),
        ];

        let g2_precomp: Vec<_> = g2_points.iter().map(|p| p.precompute()).collect();
        let miller_result = glued_miller_loop(&g2_precomp, &g1_points);
        miller_result.final_exponentiation() == Gt::identity()
    }
}

fn main() {
    // Set up the threshold signature scheme
    let t = 3; // threshold
    let n = 5; // total number of participants

    println!(
        "Initializing threshold signature scheme with t = {} and n = {}",
        t, n
    );
    let scheme = ThresholdSignature::new(t, n);

    let message = b"Hello, Sylow!";
    println!(
        "Message to be signed: {:?}",
        std::str::from_utf8(message).unwrap()
    );

    // Generate partial signatures
    println!("Generating partial signatures...");
    let mut partial_signatures = HashMap::new();
    for i in 1..=scheme.n {
        let signature = scheme.partial_sign(i, message);
        partial_signatures.insert(i, signature);
    }

    // Batch verify partial signatures
    println!("Batch verifying partial signatures...");
    assert!(
        scheme.batch_verify_partial(message, &partial_signatures),
        "Invalid partial signatures"
    );
    println!("All partial signatures verified successfully!");

    // Aggregate signatures
    println!("Aggregating partial signatures...");
    let aggregated_signature = scheme.aggregate(&partial_signatures);

    // Verify aggregated signature
    println!("Verifying aggregated signature...");
    assert!(
        scheme.verify(message, &aggregated_signature),
        "Invalid aggregated signature"
    );
    println!("Aggregated signature verified successfully!");

    println!("Threshold signature scheme demonstration completed successfully!");
}
