use crypto_bigint::U256;
use num_traits::Inv;
use sylow::{Fp, Fp2};
use tracing::info;

// TODO(What are we demonstrating here which is useful to the end user?)
fn fp_example() {
    info!("Examples with Fp...");
    let mut f = Fp::ONE;
    info!("Fp::ONE = {:?}", f);
    f = f + f;
    info!("Fp::ONE + Fp::ONE = {:?}", f);
    f *= Fp::THREE;
    info!("2 * 3 = {:?}", f);
    f /= Fp::TWO;
    info!("6 / 2 = {:?}", f);
    f /= Fp::TWO;
    info!("3 / 2 = {:?}", f);
    f += f;
    info!("(3/2) + (3/2) = {:?}", f);
    f = f.inv();
    info!("1 / 3 = {:?}", f);
    f *= Fp::THREE;
    info!("3 * (1/3) = {:?}", f);
    info!("");

    f = Fp::new(U256::from_u32(10));
    info!("10 = {:?}", f);
    info!("10.is_square() = {:?}", f.is_square());
    f = f.square();
    info!("10.square() = {:?}", f);
    f = f.sqrt().unwrap();
    info!("100.sqrt() = {:?}", f);
    info!(
        "100.sqrt().square() = {:?}",
        Fp::new(U256::from_u32(100)).sqrt().unwrap().square()
    );
    info!(
        "10 * 10 = {:?}",
        Fp::new(U256::from_u32(10)) * Fp::new(U256::from_u32(10))
    );
    info!("100.is_square() = {:?}", f.is_square());
    f = Fp::new(U256::from_u32(99));
    info!("99.is_square() = {:?}", f.is_square());
    info!("99.sgn0() = {:?}", f.sgn0());
    f = Fp::new_from_str("42").unwrap();
    info!("Fp::new_from_str(\"42\") = {:?}", f);
    info!("Fp::characteristic() = {:?}", Fp::characteristic());

    info!("");
}

fn fp2_example() {
    info!("Examples with Fp2...");

    let mut f = Fp2::new(&[Fp::ONE, Fp::ONE]);
    info!("(1,1) = {:?}", f);
    f *= f;
    info!("(1,1) + (1,1) = {:?}", f + f);
    info!("(1,1) * (1,1) = {:?}", f * f);
    info!("(1,1).inv() = {:?}", f.inv());
    info!("(1,1).pow(3) = {:?}", f.pow(&Fp::THREE));
    info!("(1,1).sqrt() = {:?}", f.sqrt().unwrap());

    let two = Fp2::new(&[Fp::TWO, Fp::TWO]);
    info!("(2,2).sqrt() = {:?}", two.sqrt().unwrap());
    info!("(2,2).sqrt().square() = {:?}", two.sqrt().unwrap().square());
}

fn main() {
    tracing_subscriber::fmt().init();

    fp_example();
    fp2_example();
}
