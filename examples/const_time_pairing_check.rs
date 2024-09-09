use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::Rng;
use sylow::{sign, verify, KeyPair};

const MIN_MSG_LEN: usize = 1;
const MAX_MSG_LEN: usize = 1024;

// TODO(Move to benchmarks rather than examples)
fn generate_random_message(rng: &mut BenchRng) -> Vec<u8> {
    let len = rng.gen_range(MIN_MSG_LEN..=MAX_MSG_LEN);
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

fn bench_pairing_generation(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs = Vec::new();
    let mut classes = Vec::new();

    // Make 100,000 inputs on each run
    for _ in 0..10_000 {
        inputs.push(generate_random_message(rng));
        // Randomly pick which distribution this example belongs to
        if rng.gen::<bool>() {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }
    }

    for (msg, class) in inputs.into_iter().zip(classes.into_iter()) {
        runner.run_one(class, || {
            let key_pair = KeyPair::generate();
            match sign(&key_pair.secret_key, &msg) {
                Ok(signature) => {
                    // Verify the signature
                    match verify(&key_pair.public_key, &msg, &signature) {
                        Ok(is_valid) => {
                            assert!(is_valid, "Signature verification failed");
                        }
                        Err(e) => println!("Verification error: {:?}", e),
                    }
                }
                Err(e) => println!("Signing error: {:?}", e),
            }
        });
    }
}

ctbench_main!(bench_pairing_generation);
