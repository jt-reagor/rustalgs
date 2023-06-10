#![allow(dead_code)]

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_traits::{One, Zero};
use rand;

// create a key pair
// steps:
// 1. Find 2 primes, p and q
// 2. Calculate n = p * q
// 3. Maybe use a fixed e? (65537)
// 4. Calculate d = e^-1 (mod (p-1)(q-1)) given gcd((p-1)(q-1), e) = 1
// 5. Pub key = (n, e)  Priv key = (n, d)
pub fn gen_key(bit_size: u64) -> (BigUint, BigUint, BigUint) {
    // step 1, find 2 primes
    let (p, q) = find_2_primes(bit_size);
    // step 2, calculate n = p*q
    let n = &p * &q;
    // step 3, fixed e
    let e = 65537.to_biguint().unwrap();
    // step 4
    let dmod = (p - 1.to_biguint().unwrap()) * (q - 1.to_biguint().unwrap());
    // quick check for rel prime?
    if (&dmod % &e).is_zero() {
        println!("Not relatively prime");
        let (n, e, d) = gen_key(bit_size); // recursive backtracking
        return (n, e, d);
    }
    let (d, _) = eea(&e, &dmod); // calculate d by eea
    let dmod = dmod.to_bigint().unwrap(); // cast to bigint from unsigned
    let mut d = d % &dmod;
    // had to add this in because for some reason modulo can return negatives?
    if d < 0.to_bigint().unwrap() {
        d += dmod;
    }
    let d = d
        .to_biguint()
        .expect(format!("d returned negative: {d}").as_str()); // careful here... should be positive.
    return (n, e, d);
}

fn find_2_primes(bit_size: u64) -> (BigUint, BigUint) {
    let p = get_prime(bit_size/2, 2);
    let q = get_prime(bit_size/2, 2);
    return (p, q);
}

// this seems to work
pub fn get_prime(bit_size: u64, trials: i32) -> BigUint {
    let mut rng = rand::thread_rng();
    loop {
        let mut p = rng.gen_biguint(bit_size); // get some random number

        // the next two lines ensure that the last bit is 1
        // this may not be necessary
        let bit_mask: BigUint = 1.to_biguint().unwrap() << (bit_size-1); // mask 0x1000...
        p = &p | bit_mask; // OR mask into p to set last bit

        if ((&p) % 2.to_biguint().unwrap()).is_zero() { // check if even, if so add 1
            p = p + 1.to_biguint().unwrap();
        }
        if f_test(&p, trials) { // check if prime via fermat's primality test
            // let bit_len = format!("{p:b}").len();
            // println!("{bit_len}");
            return p;
        }
    }
}

// fermat's primality test
pub fn f_test(p: &BigUint, trials: i32) -> bool {
    let mut rng = rand::thread_rng();
    for _ in 0..trials { // can do multiple trials to be certain it isn't a false prime
        let low = 2.to_biguint().unwrap(); // lower bound for a
        let high = &p; // upper bound for a
        let a = rng.gen_biguint_range(&low, &high);
        let psubone = p - 1.to_biguint().unwrap();
        if !a.modpow(&psubone, p).is_one() { // if a^(p-1) = 1 (mod p) then p is likely prime
            return false; // here we check if NOT 1 so that we can iterate over our trials
        }
    }
    // println!("{p} is probably prime.");

    // if passed all trials and a^(p-1) != 1 (mod p) then p is likely prime
    return true;
}

// this can definitely be optimized... but it works for now
pub fn eea(a: &BigUint, b: &BigUint) -> (BigInt, BigInt) {
    let mut r1 = a.to_bigint().unwrap();
    let mut r2 = b.to_bigint().unwrap();
    let mut c1r1 = 1.to_bigint().unwrap();
    let mut c1r2 = 0.to_bigint().unwrap();
    let mut c2r1 = 0.to_bigint().unwrap();
    let mut c2r2 = 1.to_bigint().unwrap();
    while !(&r2.is_zero()) {
        // println!("{q} {r1} {c1r1} {c2r1}");
        let q = &r1 / &r2;
        let mut temp = (&r1).clone();
        r1 = r2.clone();
        r2 = temp % r2;

        temp = (&c1r2).clone();
        c1r2 = &c1r1 - (&c1r2 * &q);
        c1r1 = temp.clone();

        temp = (&c2r2).clone();
        c2r2 = &c2r1 - (&c2r2 * &q);
        c2r1 = temp.clone();
    }
    // println!("{q} {r1} {c1r1} {c2r1}");
    return (c1r1, c2r1);
}

// easy modular exponentiation alg that I learned in cryptography
pub fn modexp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let exp_bin_str = format!("{exp:b}");
    return exp_bin_str.chars().fold(1.to_biguint().unwrap(), |acc, bit| {
        if bit == '1' {
            // ((&acc * &acc) % &modulus) * &base % &modulus
            &acc * &acc * base % modulus
        }else{
            &acc * &acc % modulus
        }
    });
}

pub fn encrypt(plain: &BigUint, pub_key: &BigUint, modulus: &BigUint) -> BigUint {
    return modexp(plain, pub_key, modulus);
}

pub fn decrypt(cipher: &BigUint, priv_key: &BigUint, modulus: &BigUint) -> BigUint {
    return modexp(cipher, priv_key, modulus);
}

// -------------------------------UNIT TESTS--------------------------------------------

#[cfg(test)]
mod tests {    
    use super::*;
    #[test]
    fn test_encrypt_decrypt() {
        for _ in 0..10 {
            let (n, e, d) = gen_key(50);
            let plaintext = get_prime(45, 2);
            let ciphertext = encrypt(&plaintext, &e, &n);
            let decrypted = decrypt(&ciphertext, &d, &n);
        
            assert_eq!(plaintext, decrypted);
        }
    }
}