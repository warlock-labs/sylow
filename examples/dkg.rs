use crypto_bigint::rand_core::OsRng;
use crypto_bigint::U256;
use num_traits::{One, Pow, Zero};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use sylow::{FieldExtensionTrait, Fp};
use tracing::{event, Level};

const GENERATOR: Fp = Fp::new(U256::from_u64(3u64));

// TODO: Bounding coefficients until we address exponent modulo arithmetic
const MIN_COEFFICIENT: u64 = 1;
const MAX_COEFFICIENT: u64 = 1000;

fn generate_distinct_random_values(count: usize, min: u64, max: u64) -> Vec<Fp> {
    let mut values = HashSet::new();

    while values.len() < count {
        let value =
            <Fp as FieldExtensionTrait<1, 1>>::rand(&mut OsRng) % Fp::from(max) + Fp::from(min);
        values.insert(value.value());
    }

    values.into_iter().map(|n| Fp::new(n)).collect()
}

#[allow(dead_code)]
struct DealerSecret {
    quorum: u32,
    round_id: u64,
    coefficients: Vec<Fp>,
    secret: Fp,
    commitments: Vec<Fp>,
}

impl DealerSecret {
    fn new(quorum: u32, round_id: u64) -> Self {
        let coefficients =
            generate_distinct_random_values(quorum as usize, MIN_COEFFICIENT, MAX_COEFFICIENT);
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
    fn new_bad(quorum: u32, round_id: u64) -> Self {
        let coefficients = vec![Fp::from(42u64); quorum as usize];
        let secret = coefficients[0].clone();
        let commitments = vec![Fp::from(42u64); quorum as usize];
        DealerSecret {
            quorum,
            round_id,
            coefficients,
            secret,
            commitments,
        }
    }
}

#[allow(dead_code)]
struct DealerShare {
    round_id: u64,
    dealer_id: u64,
    commitments: Vec<Fp>,
    x: Fp,
    y: Fp,
}

#[allow(dead_code)]
struct Participant {
    participant_id: u64,
    host: String,
    dealer_secret: DealerSecret,
    dealer_shares: HashMap<u64, DealerShare>,
}

#[allow(dead_code)]
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
        Self { quorum: 0 }
    }
}

fn do_round(round_id: u64, quorum: u32) {
    event!(Level::INFO, "Begin round {round_id}");
    let mut round_data = Round {
        round_id,
        quorum,
        participants: HashMap::new(),
    };

    // set up participants
    let n_participants: u64 = (quorum + 2) as u64;
    for participant_id in 0u64..n_participants {
        let participant = Participant {
            participant_id,
            host: "some_host".to_string(),
            dealer_secret: if participant_id != (quorum + 1) as u64 {
                DealerSecret::new(quorum, round_id)
            } else {
                DealerSecret::new_bad(quorum, round_id)
            },
            dealer_shares: HashMap::new(),
        };
        round_data.participants.insert(participant_id, participant);
    }

    let mut public_key = Fp::one();

    // iterate through dealers
    for (dealer_id, dealer) in round_data.participants.iter() {
        let dealer_secret = &dealer.dealer_secret;
        let x_shares =
            generate_distinct_random_values(quorum as usize, MIN_COEFFICIENT, MAX_COEFFICIENT);
        let recipient_index = 0;
        let mut complaint_count = 0;

        for (recipient_id, _recipient) in round_data.participants.iter() {
            if dealer_id == recipient_id {
                continue;
            }

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
            if !share_valid {
                // complaint broadcast and validation would go here
                complaint_count += 1;
            }
            event!(Level::INFO, "round_id: {round_id} dealer_id: {dealer_id} recipient_id: {recipient_id} share_valid: {share_valid}");
        }

        if complaint_count >= n_participants / 2 {
            event!(Level::ERROR, "round_id: {round_id} dealer_id: {dealer_id} kicked for {complaint_count}/{n_participants} complaints");
        } else {
            public_key *= dealer.dealer_secret.commitments[0];
        }
    }

    event!(Level::INFO, "Aggregate public key: {}", public_key.value());
    event!(Level::INFO, "End round {round_id}");
}

fn main() -> Result<(), confy::ConfyError> {
    tracing_subscriber::fmt().init();
    event!(Level::INFO, "Begin dkg::main");
    let config_path = PathBuf::from("examples/dkg.toml");
    let cfg: MyConfig = confy::load_path(&config_path)?;
    event!(Level::INFO, "Loaded config: {:?}", cfg);

    const NUMBER_OF_ROUNDS: u64 = 3;
    for round_id in 0..NUMBER_OF_ROUNDS {
        do_round(round_id, cfg.quorum);
    }

    event!(Level::INFO, "End dkg::main");
    Ok(())
}
