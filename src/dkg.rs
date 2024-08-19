use crypto_bigint::U256;
use std::collections::HashMap;
use num_traits::{One, Pow, Zero};
use crate::fields::fp::Fp;
use tracing::{event, Level};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use rand::Rng;
use std::collections::HashSet;

const GENERATOR: Fp = Fp::new(U256::from_u64(3u64));

// TODO: Bounding coefficients until we address exponent modulo arithmetic
const MIN_COEFFICIENT: u32 = 1;
const MAX_COEFFICIENT: u32 = 1000;

fn generate_distinct_random_values(count: usize, min: u32, max: u32) -> Vec<u32> {
    let mut rng = rand::thread_rng();
    let mut values = HashSet::new();

    while values.len() < count {
        let value = rng.gen_range(min..=max);
        values.insert(value);
    }

    values.into_iter().collect()
}

fn from_u32(n: u32) -> Fp {
    Fp::new(U256::from_u64(n as u64))
}

fn from_vec_u32(v: Vec<u32>) -> Vec<Fp> {
    v.iter().map(|n| from_u32(*n)).collect()
}

struct DealerSecret {
    quorum: u32,
    round_id: u64,
    coefficients: Vec<Fp>,
    secret: Fp,
    commitments: Vec<Fp>,
}

impl DealerSecret {
    fn new(quorum: u32, round_id: u64) -> Self {
        let coefficients = from_vec_u32(generate_distinct_random_values(quorum as usize, MIN_COEFFICIENT, MAX_COEFFICIENT));
        let secret = coefficients[0].clone();
        let commitments = coefficients
            .iter()
            .map(|c| GENERATOR.pow(c.value()))
            .collect();
        DealerSecret {
            quorum,
            round_id,
            coefficients,
            secret,
            commitments,
        }
    }
}
struct DealerShare {
    round_id: u64,
    dealer_id: u64,
    commitments: Vec<Fp>,
    x: Fp,
    y: Fp,
}

struct Participant {
    participant_id: u64,
    host: String,
    dealer_secret: DealerSecret,
    dealer_shares: HashMap<u64, DealerShare>,
}

struct Round {
    round_id: u64,
    quorum: u32,
    participants: HashMap<u64, Participant>,
}

// The coefficients are [a_0,...,a_n], and so this evaluates sum(a_i x^i).
impl DealerSecret {
    fn eval_polynomial(&self, x: Fp) -> Fp {
        let mut val = Fp::zero();
        for (i, c) in self.coefficients.iter().enumerate() {
            val += *c * x.pow(U256::from_u64(i as u64));
        }
        val
    }
}

impl DealerShare {
    fn is_valid(&self) -> bool {
        let commitments_val = self.eval_commitments();
        let share_val = GENERATOR.pow(self.y.value());
        commitments_val == share_val
    }

    fn eval_commitments(&self) -> Fp {
        let mut val = Fp::one();
        for (j, cmt_j) in self.commitments.iter().enumerate() {
            val *= cmt_j.pow(self.x.pow(U256::from_u64(j as u64)).value());
        }
        val
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MyConfig {
    quorum: u32,
}

impl Default for MyConfig {
    fn default() -> Self {
        Self {
            quorum: 0,
        }
    }
}

fn do_round(round_id: u64, quorum: u32) {
    let mut round_data = Round {
        round_id,
        quorum,
        participants: HashMap::new(),
    };

    // set up participants
    let n_participants: u64 = (quorum + 1) as u64;
    for participant_id in 0u64..n_participants {
        let participant = Participant {
            participant_id,
            host: "todo".to_string(),
            dealer_secret: DealerSecret::new(quorum, round_id),
            dealer_shares: HashMap::new(),
        };
        round_data.participants.insert(participant_id, participant);
    }

    // iterate through dealers
    for (dealer_id, dealer) in round_data.participants.iter() {
        let dealer_secret = &dealer.dealer_secret;
        let x_shares = from_vec_u32(generate_distinct_random_values(quorum as usize, MIN_COEFFICIENT, MAX_COEFFICIENT));
        let recipient_index = 0;
        for (recipient_id, recipient) in round_data.participants.iter() {
            let x_share = x_shares[recipient_index];
            let y_share = dealer_secret.eval_polynomial(x_share);
            let share = DealerShare {
                round_id,
                dealer_id: *dealer_id,
                commitments: dealer_secret.commitments.clone(),
                x: x_share,
                y: y_share,
            };
            let share_valid = share.is_valid();
            event!(Level::INFO, "round_id: {round_id} dealer_id: {dealer_id} recipient_id: {recipient_id} share_valid: {share_valid}");
        }
    }
}

#[test]
fn main() -> Result<(), confy::ConfyError> {
    tracing_subscriber::fmt().init();
    event!(Level::INFO, "Begin dkg::main");
    let config_path = PathBuf::from("dkg.toml");
    let cfg: MyConfig = confy::load_path(&config_path)?;
    event!(Level::INFO, "Loaded config: {:?}", cfg);

    const NUMBER_OF_ROUNDS: u64 = 3;
    for round_id in 0..NUMBER_OF_ROUNDS {
        do_round(round_id, cfg.quorum);
    }

    event!(Level::INFO, "End dkg::main");
    Ok(())
}
