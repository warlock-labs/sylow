use crypto_bigint::rand_core::OsRng;
use crypto_bigint::U256;
use num_traits::{One, Pow, Zero};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use sylow::{FieldExtensionTrait, Fp};
use tracing::{event, Level};

const GENERATOR: Fp = Fp::THREE;

// TODO: Bounding coefficients until we address exponent modulo arithmetic
const MIN_COEFFICIENT: u64 = 1;
const MAX_COEFFICIENT: u64 = 1000;

fn generate_distinct_random_values(count: usize, min: u64, max: u64) -> Vec<Fp> {
    let mut values = HashSet::new();

    while values.len() < count {
        let value =
            <Fp as FieldExtensionTrait<1, 1>>::rand(&mut OsRng) % Fp::from(max) + Fp::from(min);
        values.insert(value);
    }

    values.into_iter().collect()
}

struct DealerSecret {
    // polynomial coefficients; coefficients[0] is the secret a_0
    coefficients: Vec<Fp>,
    commitments: Vec<Fp>,
}

impl DealerSecret {
    fn new(quorum: u32) -> Self {
        let coefficients =
            generate_distinct_random_values(quorum as usize, MIN_COEFFICIENT, MAX_COEFFICIENT);
        let commitments = coefficients
            .iter()
            .map(|c| GENERATOR.pow(c.value()))
            .collect();
        DealerSecret {
            coefficients,
            commitments,
        }
    }
    fn new_bad(quorum: u32) -> Self {
        let coefficients = vec![Fp::from(42u64); quorum as usize];
        let commitments = vec![Fp::from(42u64); quorum as usize];
        DealerSecret {
            coefficients,
            commitments,
        }
    }
}

struct DealerShare {
    commitments: Vec<Fp>,
    x: Fp,
    y: Fp,
}

struct Participant {
    dealer_secret: DealerSecret,
}

struct Round {
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
        let mut val = Fp::ONE;
        for (j, cmt_j) in self.commitments.iter().enumerate() {
            val *= cmt_j.pow(self.x.pow(U256::from_u64(j as u64)).value());
        }
        val
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MyConfig {
    quorum: u32,
}

fn do_round(round_id: u64, quorum: u32) {
    event!(Level::INFO, "Begin round {round_id}");
    let mut round_data = Round {
        participants: HashMap::new(),
    };

    // set up participants
    let n_participants: u64 = (quorum + 2) as u64;
    for participant_id in 0u64..n_participants {
        let participant = Participant {
            dealer_secret: if participant_id != (quorum + 1) as u64 {
                DealerSecret::new(quorum)
            } else {
                DealerSecret::new_bad(quorum)
            },
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
    let cfg: MyConfig = confy::load_path(config_path)?;
    event!(Level::INFO, "Loaded config: {:?}", cfg);

    const NUMBER_OF_ROUNDS: u64 = 3;
    for round_id in 0..NUMBER_OF_ROUNDS {
        do_round(round_id, cfg.quorum);
    }

    event!(Level::INFO, "End dkg::main");
    Ok(())
}
