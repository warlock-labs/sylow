use sylow::{pairing, G1Projective, G2Projective, GroupTrait};

const RANGE: usize = 100;

fn main() {
    let a = G1Projective::generator();
    let b = G2Projective::generator();
    // let c = Fp::from(Fr::new_from_str("1901").unwrap().inv());
    // let d = Fp::from(Fr::new_from_str("2344").unwrap().inv());

    for _ in 0..RANGE {
        let _ = pairing(&a, &b);
        // a = a * c;
        // b = b * d;
    }
}
