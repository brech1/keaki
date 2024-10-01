//! # Key Encapsulation Mechanism
//!
//! This module implements the **Extractable Witness Key Encapsulation Mechanism** functions.

use crate::kzg::{g1_gen, g2_gen, KZGError, KZG};
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;
use ark_std::{rand, UniformRand};
use blake3::OutputReader;
use rand::thread_rng;
use std::ops::Mul;
use thiserror::Error;

/// Encapsulation.
/// Generates a key for a commitment and a point-value pair.
pub fn encapsulate<E: Pairing>(
    kzg: &KZG<E>,
    commitment: E::G1,
    point: E::ScalarField,
    value: E::ScalarField,
) -> Result<(E::G2, OutputReader), KEMError> {
    // [beta]_1
    let value_in_g1: E::G1 = g1_gen::<E>().mul(value);

    // (com - [beta]_1)
    let com_beta = commitment - value_in_g1;

    // Generate a random value
    // This allows the generated secret not to be tied to the inputs.
    let mut rng = thread_rng();
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
    let tau_alpha: E::G2 = kzg.tau_g2()? - g2_gen::<E>().mul(point);
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

/// Encapsulates a set of points and values for a commitment.
/// Returns the keys and ciphertexts.
pub fn encapsulate_set<E: Pairing>(
    kzg: &KZG<E>,
    commitment: E::G1,
    points: &[E::ScalarField],
    values: &[E::ScalarField],
) -> Result<(Vec<E::G2>, Vec<OutputReader>), KEMError> {
    if points.len() != values.len() {
        return Err(KEMError::EncapsulationInputsLengthError);
    }

    points
        .iter()
        .zip(values.iter())
        .map(|(&point, &value)| encapsulate::<E>(kzg, commitment, point, value))
        .collect::<Result<Vec<_>, _>>()
        .map(|v| v.into_iter().unzip())
}

/// Decapsulates a set of proofs and ciphertexts.
/// Returns the keys.
pub fn decapsulate_set<E: Pairing>(
    proofs: &[E::G1],
    ciphertexts: &[E::G2],
) -> Result<Vec<OutputReader>, KEMError> {
    if proofs.len() != ciphertexts.len() {
        return Err(KEMError::DecapsulationInputsLengthError);
    }

    proofs
        .iter()
        .zip(ciphertexts.iter())
        .map(|(&proof, &ciphertext)| decapsulate::<E>(proof, ciphertext))
        .collect()
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum KEMError {
    #[error("Proofs and ciphertexts sets must have the same length")]
    DecapsulationInputsLengthError,
    #[error("Points and values sets must have the same length")]
    EncapsulationInputsLengthError,
    #[error("KZG error: {0}")]
    KZGError(KZGError),
    #[error("Secret serialization failed {0}")]
    SerializationError(String),
}

impl From<KZGError> for KEMError {
    fn from(err: KZGError) -> Self {
        KEMError::KZGError(err)
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use crate::pol_op::evaluate_polynomial;
    // use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    // use ark_std::test_rng;
    // use ark_std::UniformRand;

    // #[test]
    // fn test_encapsulation_decapsulation() {
    //     let rng = &mut test_rng();
    //     let g1_gen = G1Projective::rand(rng);
    //     let g2_gen = G2Projective::rand(rng);
    //     let secret = Fr::rand(rng);
    //     let max_degree = 10;
    //     let point: Fr = Fr::rand(rng);
    //     let kzg: KZG<Bls12_381> = KZG::setup(g1_gen, g2_gen, max_degree, secret);

    //     // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
    //     let p = vec![
    //         Fr::from(-24),
    //         Fr::from(-25),
    //         Fr::from(-5),
    //         Fr::from(9),
    //         Fr::from(7),
    //     ];
    //     let val = evaluate_polynomial::<Bls12_381>(&p, &point);
    //     let commitment = kzg.commit(&p).unwrap();

    //     // Encapsulate
    //     let (ciphertext, mut enc_key) = encapsulate(&kzg, commitment, point, val).unwrap();
    //     let mut enc_key_bytes = [0u8; 32];
    //     enc_key.fill(&mut enc_key_bytes);

    //     // Decapsulate
    //     let proof = kzg.open(&p, &point).unwrap();
    //     let mut dec_key = decapsulate::<Bls12_381>(proof, ciphertext).unwrap();
    //     let mut dec_key_bytes = [0u8; 32];
    //     dec_key.fill(&mut dec_key_bytes);

    //     assert_eq!(enc_key_bytes, dec_key_bytes);
    // }

    // #[test]
    // fn test_decapsulation_invalid_proof() {
    //     let rng = &mut test_rng();
    //     let g1_gen = G1Projective::rand(rng);
    //     let g2_gen = G2Projective::rand(rng);
    //     let secret = Fr::rand(rng);
    //     let max_degree = 10;
    //     let point: Fr = Fr::rand(rng);
    //     let kzg: KZG<Bls12_381> = KZG::setup(g1_gen, g2_gen, max_degree, secret);

    //     // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
    //     let p = vec![
    //         Fr::from(-24),
    //         Fr::from(-25),
    //         Fr::from(-5),
    //         Fr::from(9),
    //         Fr::from(7),
    //     ];
    //     let val = evaluate_polynomial::<Bls12_381>(&p, &point);
    //     let commitment = kzg.commit(&p).unwrap();

    //     // Encapsulate
    //     let (ciphertext, mut enc_key) =
    //         encapsulate::<Bls12_381>(&kzg, commitment, point, val).unwrap();
    //     let mut enc_key_bytes = [0u8; 32];
    //     enc_key.fill(&mut enc_key_bytes);

    //     // Generate an invalid proof
    //     let wrong_point: Fr = Fr::rand(rng);
    //     let invalid_proof = kzg.open(&p, &wrong_point).unwrap();

    //     // Attempt to decapsulate with the invalid proof
    //     let mut dec_key = decapsulate::<Bls12_381>(invalid_proof, ciphertext).unwrap();
    //     let mut dec_key_bytes = [0u8; 32];
    //     dec_key.fill(&mut dec_key_bytes);

    //     // The keys should not match
    //     assert_ne!(enc_key_bytes, dec_key_bytes);
    // }

    // #[test]
    // fn test_decapsulation_invalid_ciphertext() {
    //     let rng = &mut test_rng();
    //     let g1_gen = G1Projective::rand(rng);
    //     let g2_gen = G2Projective::rand(rng);
    //     let secret = Fr::rand(rng);
    //     let max_degree = 10;
    //     let point: Fr = Fr::rand(rng);
    //     let kzg: KZG<Bls12_381> = KZG::setup(g1_gen, g2_gen, max_degree, secret);

    //     // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
    //     let p = vec![
    //         Fr::from(-24),
    //         Fr::from(-25),
    //         Fr::from(-5),
    //         Fr::from(9),
    //         Fr::from(7),
    //     ];
    //     let val = evaluate_polynomial::<Bls12_381>(&p, &point);
    //     let commitment = kzg.commit(&p).unwrap();

    //     // Encapsulate
    //     let (ciphertext, mut enc_key) =
    //         encapsulate::<Bls12_381>(&kzg, commitment, point, val).unwrap();
    //     let mut enc_key_bytes = [0u8; 32];
    //     enc_key.fill(&mut enc_key_bytes);

    //     // Generate an invalid ciphertext (e.g., by using a different random value)
    //     let invalid_ciphertext = ciphertext.mul(Fr::rand(rng));

    //     // Attempt to decapsulate with the invalid ciphertext
    //     let proof = kzg.open(&p, &point).unwrap();

    //     let mut dec_key = decapsulate::<Bls12_381>(proof, invalid_ciphertext).unwrap();
    //     let mut dec_key_bytes = [0u8; 32];
    //     dec_key.fill(&mut dec_key_bytes);

    //     // The keys should not match
    //     assert_ne!(enc_key_bytes, dec_key_bytes);
    // }

    // #[test]
    // fn test_decapsulation_wrong_proof_ciphertext() {
    //     let rng = &mut test_rng();
    //     let g1_gen = G1Projective::rand(rng);
    //     let g2_gen = G2Projective::rand(rng);
    //     let secret = Fr::rand(rng);
    //     let max_degree = 10;
    //     let point1: Fr = Fr::rand(rng);
    //     let point2: Fr = Fr::rand(rng);
    //     let kzg: KZG<Bls12_381> = KZG::setup(g1_gen, g2_gen, max_degree, secret);

    //     // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
    //     let p = vec![
    //         Fr::from(-24),
    //         Fr::from(-25),
    //         Fr::from(-5),
    //         Fr::from(9),
    //         Fr::from(7),
    //     ];
    //     let val1 = evaluate_polynomial::<Bls12_381>(&p, &point1);
    //     let commitment = kzg.commit(&p).unwrap();

    //     // Encapsulate with point1
    //     let (ciphertext1, mut enc_key) =
    //         encapsulate::<Bls12_381>(&kzg, commitment, point1, val1).unwrap();
    //     let mut enc_key_bytes = [0u8; 32];
    //     enc_key.fill(&mut enc_key_bytes);

    //     // Proof for point2
    //     let proof2 = kzg.open(&p, &point2).unwrap();

    //     // Decapsulate with proof for point2
    //     let mut dec_key = decapsulate::<Bls12_381>(proof2, ciphertext1).unwrap();
    //     let mut dec_key_bytes = [0u8; 32];
    //     dec_key.fill(&mut dec_key_bytes);

    //     // Keys should not match
    //     assert_ne!(enc_key_bytes, dec_key_bytes);
    // }

    // #[test]
    // fn test_encapsulate_decapsulate_set() {
    //     let rng = &mut test_rng();
    //     let g1_gen = G1Projective::rand(rng);
    //     let g2_gen = G2Projective::rand(rng);
    //     let secret = Fr::rand(rng);
    //     let max_degree = 10;
    //     let kzg: KZG<Bls12_381> = KZG::setup(g1_gen, g2_gen, max_degree, secret);

    //     // Define the polynomial p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
    //     let p = vec![
    //         Fr::from(-24),
    //         Fr::from(-25),
    //         Fr::from(-5),
    //         Fr::from(9),
    //         Fr::from(7),
    //     ];
    //     let commitment = kzg.commit(&p).unwrap();

    //     // Define points and their corresponding values
    //     let points = vec![Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
    //     let values: Vec<Fr> = points
    //         .iter()
    //         .map(|point| evaluate_polynomial::<Bls12_381>(&p, point))
    //         .collect();

    //     // Encapsulate the set
    //     let (ciphertexts, mut enc_keys) =
    //         encapsulate_set::<Bls12_381>(&kzg, commitment, &points, &values).unwrap();
    //     let enc_keys_bytes: Vec<[u8; 32]> = enc_keys
    //         .iter_mut()
    //         .map(|enc_key| {
    //             let mut enc_key_bytes = [0u8; 32];
    //             enc_key.fill(&mut enc_key_bytes);
    //             enc_key_bytes
    //         })
    //         .collect();

    //     // Generate proofs for the points
    //     let proofs: Vec<G1Projective> = points
    //         .iter()
    //         .map(|point| kzg.open(&p, point).unwrap())
    //         .collect();

    //     // Decapsulate the set
    //     let mut dec_keys = decapsulate_set::<Bls12_381>(&proofs, &ciphertexts).unwrap();
    //     let dec_keys_bytes: Vec<[u8; 32]> = dec_keys
    //         .iter_mut()
    //         .map(|dec_key| {
    //             let mut dec_key_bytes = [0u8; 32];
    //             dec_key.fill(&mut dec_key_bytes);
    //             dec_key_bytes
    //         })
    //         .collect();

    //     // Compare the encapsulated and decapsulated keys
    //     for (enc_key_bytes, dec_key_bytes) in enc_keys_bytes.iter().zip(dec_keys_bytes.iter()) {
    //         assert_eq!(enc_key_bytes, dec_key_bytes);
    //     }
    // }
}
