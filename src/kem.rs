//! # Key Encapsulation Mechanism
//!
//! This module implements the **Extractable Witness Key Encapsulation Mechanism** functions.

use crate::kzg::KZGSetup;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Mul, vec::Vec, UniformRand};

/// Encapsulation.
/// Generates a key for a commitment and a point-value pair.
pub fn encapsulate<E: Pairing>(
    rng: &mut impl rand::Rng,
    kzg_setup: &KZGSetup<E>,
    commitment: E::G1,
    point: E::ScalarField,
    value: E::ScalarField,
    msg_len: usize,
) -> (E::G2, Vec<u8>) {
    // (com - [beta]_1)
    let com_beta = commitment - E::G1Affine::generator().mul(value);

    // Generate a random value
    // This allows the generated secret not to be tied to the inputs.
    let r = E::ScalarField::rand(rng);

    // Calculate secret
    // s = e(r * (com - [beta]_1), g2)
    let secret = E::pairing(com_beta.mul(r), E::G2Affine::generator());
    let mut secret_bytes = Vec::<u8>::new();
    secret.serialize_uncompressed(&mut secret_bytes).unwrap();

    // Calculate a ciphertext to share the randomness used in the encapsulation.
    // ct = r([tau]_2 - [alpha]_2)
    let tau_alpha: E::G2 = *kzg_setup.tau_g2() - E::G2Affine::generator().mul(point);
    let ciphertext: E::G2 = tau_alpha.mul(r);

    // Generate the key
    // Hash the secret to make the key indistinguishable from random.
    // k = H(s)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&secret_bytes);

    let mut key = vec![0u8; msg_len];
    hasher.finalize_xof().fill(key.as_mut_slice());

    // (ct, k)
    (ciphertext, key)
}

/// Decapsulation.
/// Generates a key for an opening and a ciphertext.
/// The generated key will be the same as the one generated during encapsulation for a valid opening.
pub fn decapsulate<E: Pairing>(proof: E::G1, ciphertext: E::G2, msg_len: usize) -> Vec<u8> {
    // Calculate secret
    // s = e(proof, ct)
    let secret = E::pairing(proof, ciphertext);

    let mut secret_bytes = Vec::<u8>::new();
    secret.serialize_uncompressed(&mut secret_bytes).unwrap();

    // Get the key
    // k = H(s)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&secret_bytes);

    let mut key = vec![0u8; msg_len];
    hasher.finalize_xof().fill(key.as_mut_slice());

    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kzg::{commit, open, KZGSetup};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::{rand::Rng, test_rng};

    fn setup_kzg(rng: &mut impl Rng) -> KZGSetup<Bls12_381> {
        let secret = Fr::rand(rng);
        KZGSetup::<Bls12_381>::setup(secret, 10)
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        let rng = &mut test_rng();
        let kzg_setup = setup_kzg(rng);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let point: Fr = Fr::rand(rng);
        let eval = p.evaluate(&point);
        let commitment = commit(&kzg_setup, &p).unwrap();
        let test_msg = [0u8; 32];

        // Encapsulate
        let (ciphertext, enc_key) =
            encapsulate(rng, &kzg_setup, commitment, point, eval, test_msg.len());

        // Decapsulate
        let proof = open(&kzg_setup, &p, &point).unwrap();
        let dec_key = decapsulate::<Bls12_381>(proof, ciphertext, test_msg.len());

        // Assert that the keys match
        assert_eq!(enc_key, dec_key);
    }

    #[test]
    fn test_decapsulation_invalid_proof() {
        let rng = &mut test_rng();
        let kzg_setup = setup_kzg(rng);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let point: Fr = Fr::rand(rng);
        let eval = p.evaluate(&point);
        let commitment = commit(&kzg_setup, &p).unwrap();
        let test_msg = [0u8; 32];

        // Encapsulate
        let (ciphertext, enc_key) =
            encapsulate(rng, &kzg_setup, commitment, point, eval, test_msg.len());

        // Decapsulate with a different polynomial
        // q(x) = 7 x^4 + 9 x^3 - 5 x^2 - 29 x - 24
        let q = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-29),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let invalid_proof = open(&kzg_setup, &q, &point).unwrap();
        let dec_key = decapsulate::<Bls12_381>(invalid_proof, ciphertext, test_msg.len());

        // Keys should not match
        assert_ne!(enc_key, dec_key);
    }

    #[test]
    fn test_decapsulation_invalid_ciphertext() {
        let rng = &mut test_rng();
        let kzg_setup = setup_kzg(rng);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);
        let point: Fr = Fr::rand(rng);
        let eval = p.evaluate(&point);
        let commitment = commit(&kzg_setup, &p).unwrap();
        let test_msg = [0u8; 32];

        // Encapsulate
        let (ciphertext, enc_key) =
            encapsulate(rng, &kzg_setup, commitment, point, eval, test_msg.len());

        // Generate an random ciphertext
        let invalid_ciphertext = ciphertext.mul(Fr::rand(rng));

        // Attempt to decapsulate with the invalid ciphertext
        let proof = open(&kzg_setup, &p, &point).unwrap();

        let dec_key = decapsulate::<Bls12_381>(proof, invalid_ciphertext, test_msg.len());

        // Keys should not match
        assert_ne!(enc_key, dec_key);
    }

    #[test]
    fn test_decapsulation_wrong_point() {
        let rng = &mut test_rng();
        let kzg_setup = setup_kzg(rng);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let point1: Fr = Fr::rand(rng);
        let val1 = p.evaluate(&point1);
        let commitment = commit(&kzg_setup, &p).unwrap();
        let test_msg = [0u8; 32];

        // Encapsulate with point1
        let (ciphertext1, enc_key) =
            encapsulate(rng, &kzg_setup, commitment, point1, val1, test_msg.len());

        // Proof for point2
        let point2: Fr = Fr::rand(rng);
        let proof2 = open(&kzg_setup, &p, &point2).unwrap();

        // Decapsulate with proof for point2
        let dec_key = decapsulate::<Bls12_381>(proof2, ciphertext1, test_msg.len());

        // Keys should not match
        assert_ne!(enc_key, dec_key);
    }
}
