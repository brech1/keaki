//! # Key Encapsulation Mechanism
//!
//! This module implements the **Extractable Witness Key Encapsulation Mechanism** functions.

use crate::kzg::{g1_gen, g2_gen};
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Mul, vec::Vec, UniformRand};
use blake3::OutputReader;
use rand::{rngs::SmallRng, SeedableRng};
use thiserror::Error;

/// Encapsulation.
/// Generates a key for a commitment and a point-value pair.
pub fn encapsulate<E: Pairing>(
    commitment: E::G1,
    point: E::ScalarField,
    value: E::ScalarField,
    tau_g2: &E::G2,
) -> Result<(E::G2, OutputReader), KEMError> {
    // [beta]_1
    let value_in_g1: E::G1 = g1_gen::<E>().mul(value);

    // (com - [beta]_1)
    let com_beta = commitment - value_in_g1;

    // Generate a random value
    // This allows the generated secret not to be tied to the inputs.
    let mut rng = SmallRng::from_entropy();
    let r = E::ScalarField::rand(&mut rng);

    // Calculate secret
    // s = e(r * (com - [beta]_1), g2)
    let secret = E::pairing(com_beta.mul(r), g2_gen::<E>());
    let mut secret_bytes = Vec::<u8>::new();
    secret
        .serialize_uncompressed(&mut secret_bytes)
        .map_err(|e| KEMError::SerializationError(e.to_string()))?;

    // Calculate a ciphertext to share the randomness used in the encapsulation.
    // ct = r([tau]_2 - [alpha]_2)
    let tau_alpha: E::G2 = *tau_g2 - g2_gen::<E>().mul(point);
    let ciphertext: E::G2 = tau_alpha.mul(r);

    // Generate the key
    // Hash the secret to make the key indistinguishable from random.
    // k = H(s)
    let mut key_hasher = blake3::Hasher::new();
    key_hasher.update(&secret_bytes);

    // Return the key as a hash reader to enable custom key length.
    // (ct, k)
    Ok((ciphertext, key_hasher.finalize_xof()))
}

/// Decapsulation.
/// Generates a key for an opening and a ciphertext.
/// The generated key will be the same as the one generated during encapsulation for a valid opening.
pub fn decapsulate<E: Pairing>(proof: E::G1, ciphertext: E::G2) -> Result<OutputReader, KEMError> {
    // Calculate secret
    // s = e(proof, ct)
    let secret = E::pairing(proof, ciphertext);

    let mut secret_bytes = Vec::<u8>::new();
    secret
        .serialize_uncompressed(&mut secret_bytes)
        .map_err(|e| KEMError::SerializationError(e.to_string()))?;

    // Get the key
    // k = H(s)
    let mut key_hasher = blake3::Hasher::new();
    key_hasher.update(&secret_bytes);

    // Return the key as a hash reader to enable custom key length.
    Ok(key_hasher.finalize_xof())
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum KEMError {
    #[error("Proofs and ciphertexts sets must have the same length")]
    DecapsulationInputsLengthError,
    #[error("Points and values sets must have the same length")]
    EncapsulationInputsLengthError,
    #[error("Secret serialization failed {0}")]
    SerializationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kzg::KZG;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::{rand::Rng, test_rng};

    fn setup_kzg(rng: &mut impl Rng) -> KZG<Bls12_381> {
        let secret = Fr::rand(rng);
        KZG::<Bls12_381>::setup(secret, 10)
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        let rng = &mut test_rng();
        let kzg = setup_kzg(rng);

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
        let commitment = kzg.commit(&p).unwrap();

        // Encapsulate
        let (ciphertext, mut enc_key) =
            encapsulate::<Bls12_381>(commitment, point, eval, kzg.tau_g2()).unwrap();
        let mut enc_key_bytes = [0u8; 32];
        enc_key.fill(&mut enc_key_bytes);

        // Decapsulate
        let proof = kzg.open(&p, &point).unwrap();
        let mut dec_key = decapsulate::<Bls12_381>(proof, ciphertext).unwrap();
        let mut dec_key_bytes = [0u8; 32];
        dec_key.fill(&mut dec_key_bytes);

        // Assert that the keys match
        assert_eq!(enc_key_bytes, dec_key_bytes);
    }

    #[test]
    fn test_decapsulation_invalid_proof() {
        let rng = &mut test_rng();
        let kzg = setup_kzg(rng);

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
        let commitment = kzg.commit(&p).unwrap();

        // Encapsulate
        let (ciphertext, mut enc_key) =
            encapsulate::<Bls12_381>(commitment, point, eval, kzg.tau_g2()).unwrap();
        let mut enc_key_bytes = [0u8; 32];
        enc_key.fill(&mut enc_key_bytes);

        // Decapsulate with a different polynomial
        // q(x) = 7 x^4 + 9 x^3 - 5 x^2 - 29 x - 24
        let q = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-29),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let invalid_proof = kzg.open(&q, &point).unwrap();
        let mut dec_key = decapsulate::<Bls12_381>(invalid_proof, ciphertext).unwrap();
        let mut dec_key_bytes = [0u8; 32];
        dec_key.fill(&mut dec_key_bytes);

        // Keys should not match
        assert_ne!(enc_key_bytes, dec_key_bytes);
    }

    #[test]
    fn test_decapsulation_invalid_ciphertext() {
        let rng = &mut test_rng();
        let kzg = setup_kzg(rng);

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
        let commitment = kzg.commit(&p).unwrap();

        // Encapsulate
        let (ciphertext, mut enc_key) =
            encapsulate::<Bls12_381>(commitment, point, eval, kzg.tau_g2()).unwrap();
        let mut enc_key_bytes = [0u8; 32];
        enc_key.fill(&mut enc_key_bytes);

        // Generate an random ciphertext
        let invalid_ciphertext = ciphertext.mul(Fr::rand(rng));

        // Attempt to decapsulate with the invalid ciphertext
        let proof = kzg.open(&p, &point).unwrap();

        let mut dec_key = decapsulate::<Bls12_381>(proof, invalid_ciphertext).unwrap();
        let mut dec_key_bytes = [0u8; 32];
        dec_key.fill(&mut dec_key_bytes);

        // Keys should not match
        assert_ne!(enc_key_bytes, dec_key_bytes);
    }

    #[test]
    fn test_decapsulation_wrong_point() {
        let rng = &mut test_rng();
        let kzg = setup_kzg(rng);

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
        let commitment = kzg.commit(&p).unwrap();

        // Encapsulate with point1
        let (ciphertext1, mut enc_key) =
            encapsulate::<Bls12_381>(commitment, point1, val1, kzg.tau_g2()).unwrap();
        let mut enc_key_bytes = [0u8; 32];
        enc_key.fill(&mut enc_key_bytes);

        // Proof for point2
        let point2: Fr = Fr::rand(rng);
        let proof2 = kzg.open(&p, &point2).unwrap();

        // Decapsulate with proof for point2
        let mut dec_key = decapsulate::<Bls12_381>(proof2, ciphertext1).unwrap();
        let mut dec_key_bytes = [0u8; 32];
        dec_key.fill(&mut dec_key_bytes);

        // Keys should not match
        assert_ne!(enc_key_bytes, dec_key_bytes);
    }
}
