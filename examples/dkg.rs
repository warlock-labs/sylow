use num_traits::{Inv, One, Zero};
use serde::{Deserialize, Serialize};
use sha3::Keccak256;
use std::collections::HashMap;
use std::path::PathBuf;
use sylow::{
    glued_miller_loop, FieldExtensionTrait, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
    GroupTrait, Gt, XMDExpander,
};
use tracing::{debug, error, info, warn};

/// Domain Separation Tag for hash-to-curve operations
const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";

/// Security parameter in bits
const SECURITY_BITS: u64 = 128;

/// Configuration for the DKG scheme
#[derive(Debug, Serialize, Deserialize, Default)]
struct DkgConfig {
    /// Minimum number of participants required to reconstruct the secret
    quorum: u32,
    /// Total number of participants in the DKG scheme
    n_participants: u32,
    /// Number of DKG rounds to perform
    n_rounds: u32,
}

/// Represents a participant in the DKG scheme
#[derive(Clone, Debug)]
struct Participant {
    /// Unique identifier for the participant
    id: usize,
    /// Participant's secret key share
    secret_key: Fr,
    /// Participant's public key share
    public_key: G2Projective,
}

/// Represents the DKG scheme
struct DistributedKeyGeneration {
    /// Threshold number of participants required to reconstruct the secret
    t: usize,
    /// Total number of participants
    n: usize,
    /// List of all participants
    participants: Vec<Participant>,
    /// Group public key
    group_public_key: G2Projective,
}

impl DistributedKeyGeneration {
    /// Creates a new DKG scheme
    ///
    /// # Arguments
    ///
    /// * `t` - Threshold number of participants required to reconstruct the secret
    /// * `n` - Total number of participants
    ///
    /// # Panics
    ///
    /// Panics if `t` is greater than `n`
    fn new(t: usize, n: usize) -> Self {
        assert!(
            t <= n,
            "Threshold must be less than or equal to the number of participants"
        );

        let mut rng = rand::thread_rng();
        let secret_polynomial: Vec<Fr> = (0..t).map(|_| Fr::rand(&mut rng)).collect();

        let participants: Vec<Participant> = (1..=n)
            .map(|id| {
                let secret_key = Self::evaluate_polynomial(&secret_polynomial, id);
                let public_key = G2Projective::generator() * Fr::into(secret_key);
                Participant {
                    id,
                    secret_key,
                    public_key,
                }
            })
            .collect();

        let group_public_key = G2Projective::generator() * Fr::into(secret_polynomial[0]);

        DistributedKeyGeneration {
            t,
            n,
            participants,
            group_public_key,
        }
    }

    /// Evaluates a polynomial at a given point
    ///
    /// # Arguments
    ///
    /// * `coeffs` - Coefficients of the polynomial
    /// * `x` - Point at which to evaluate the polynomial
    ///
    /// # Returns
    ///
    /// The value of the polynomial at point `x` as an [`Fr`] element
    fn evaluate_polynomial(coeffs: &[Fr], x: usize) -> Fr {
        let x = Fr::from(x as u64);
        coeffs
            .iter()
            .rev()
            .fold(Fr::zero(), |acc, coeff| acc * x + *coeff)
    }

    /// Generates a partial signature for a given message and participant
    ///
    /// # Arguments
    ///
    /// * `participant_id` - ID of the participant generating the partial signature
    /// * `message` - Message to be signed
    ///
    /// # Returns
    ///
    /// A partial signature as a [`G1Projective`] point
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
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signatures` - A map of participant IDs to their partial signatures
    ///
    /// # Returns
    ///
    /// `true` if all partial signatures are valid, `false` otherwise
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
    ///
    /// # Arguments
    ///
    /// * `partial_signatures` - A map of participant IDs to their partial signatures
    ///
    /// # Returns
    ///
    /// The aggregated signature as a [`G1Projective`] point
    ///
    /// # Panics
    ///
    /// Panics if there are not enough partial signatures to meet the threshold
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
    ///
    /// # Arguments
    ///
    /// * `i` - ID of the participant
    /// * `participants` - List of participant IDs involved in the signature
    ///
    /// # Returns
    ///
    /// The Lagrange coefficient as an [`Fr`] element
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
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The aggregated signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
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

/// Runs a single round of the DKG protocol
///
/// # Arguments
///
/// * `round_id` - The ID of the current round
/// * `config` - The DKG configuration
///
/// # Returns
///
/// The group public key for this round as a [`G2Projective`] point
fn run_dkg_round(round_id: u32, config: &DkgConfig) -> G2Projective {
    info!("Begin round {}", round_id);

    let dkg = DistributedKeyGeneration::new(config.quorum as usize, config.n_participants as usize);

    let message = b"Hello, Sylow!";
    debug!("Generating partial signatures...");
    let mut partial_signatures = HashMap::new();
    for i in 1..=dkg.n {
        let signature = dkg.partial_sign(i, message);
        partial_signatures.insert(i, signature);
    }

    debug!("Batch verifying partial signatures...");
    let signatures_valid = dkg.batch_verify_partial(message, &partial_signatures);
    if signatures_valid {
        info!("All partial signatures verified successfully!");
    } else {
        warn!("Some partial signatures failed verification");
    }

    debug!("Aggregating partial signatures...");
    let aggregated_signature = dkg.aggregate(&partial_signatures);

    debug!("Verifying aggregated signature...");
    let aggregated_valid = dkg.verify(message, &aggregated_signature);
    if aggregated_valid {
        info!("Aggregated signature verified successfully!");
    } else {
        error!("Aggregated signature verification failed");
    }

    info!("Round {} completed", round_id);
    dkg.group_public_key
}

fn main() -> Result<(), confy::ConfyError> {
    tracing_subscriber::fmt().init();
    info!("Begin DKG process");

    let config_path = PathBuf::from("examples/dkg.toml");
    let cfg: DkgConfig = confy::load_path(config_path)?;
    debug!("Loaded config: {:?}", cfg);

    let mut aggregate_public_key = G2Projective::default();

    for round_id in 0..cfg.n_rounds {
        let round_public_key = run_dkg_round(round_id, &cfg);
        aggregate_public_key = aggregate_public_key + round_public_key;
    }

    info!("DKG process completed");
    debug!(
        "Aggregate public key across all rounds: {:?}",
        aggregate_public_key
    );
    Ok(())
}
