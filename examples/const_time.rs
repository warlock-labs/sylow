use dudect_bencher::{ctbench_main, BenchRng, CtRunner, Class};
use rand::Rng;
use sylow::{FieldExtensionTrait, Fp, Fr, G1Projective, GroupTrait, XMDExpander};
use sha3::Keccak256;

const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
const K: u64 = 128;
const MIN_MSG_LEN: usize = 1;
const MAX_MSG_LEN: usize = 1024;

fn generate_random_message(rng: &mut BenchRng) -> Vec<u8> {
    let len = rng.gen_range(MIN_MSG_LEN..=MAX_MSG_LEN);
    (0..len).map(|_| rng.gen::<u8>()).collect()
}


fn bench_signature_generation(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs = Vec::new();
    let mut classes = Vec::new();

    let expander = XMDExpander::<Keccak256>::new(DST, K);
    let private_key = Fp::new(Fr::rand(rng).value());

    // Make 100,000 inputs on each run
    for _ in 0..100 {
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
            if let Ok(hashed_message) = G1Projective::hash_to_curve(&expander, &msg) {
                let _signature = hashed_message * private_key;
            }
        });
    }
}

ctbench_main!(bench_signature_generation);