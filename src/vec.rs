//! # Vector
//!
//! This module provides helper functions for vector operations.

use crate::{
    enc::{decrypt, encrypt, Ciphertext},
    kzg::{commit, open_fk, KZGSetup},
};
use ark_ec::pairing::Pairing;
use ark_poly::{
    domain::EvaluationDomain, polynomial::univariate::DensePolynomial, DenseUVPolynomial,
    Radix2EvaluationDomain,
};
use ark_std::UniformRand;

/// Padding length.
/// Padding the vector with randomness is necessary since the commitment could leak information.
pub const PADDING_LEN: usize = 1;

/// Vector commitment.
/// Returns the commitment and the proofs for each index.
pub fn vec_commit<E: Pairing>(
    rng: &mut impl rand::Rng,
    kzg_setup: &KZGSetup<E>,
    vec: &[E::ScalarField],
) -> Result<(E::G1, Vec<E::G1>), &'static str> {
    let d = vec.len() + PADDING_LEN;
    let mut padded_vec = Vec::with_capacity(d);
    padded_vec.extend_from_slice(vec);

    // Insert random value
    let r = E::ScalarField::rand(rng);
    padded_vec.push(r);

    // Transform the vector into a polynomial in coefficient form
    let domain = Radix2EvaluationDomain::<<E as Pairing>::ScalarField>::new(d).unwrap();
    let p_coeff = domain.ifft(&padded_vec);

    // Calculate proofs for each index
    let proofs = open_fk(kzg_setup, &p_coeff, &domain).unwrap();

    // Construct the dense polynomial from the coefficients
    let p_dense = DensePolynomial::from_coefficients_vec(p_coeff);

    // Commit
    let com = commit(kzg_setup, &p_dense).unwrap();

    Ok((com, proofs))
}

/// Vector Encryption.
pub fn vec_encrypt<E: Pairing>(
    rng: &mut impl rand::Rng,
    kzg_setup: &KZGSetup<E>,
    com: E::G1,
    points: &[E::ScalarField],
    values: &[E::ScalarField],
    messages: &[&[u8]],
) -> Vec<Ciphertext<E>> {
    let len = messages.len();
    let mut cts = Vec::with_capacity(len);

    for i in 0..len {
        let ct = encrypt::<E>(rng, kzg_setup, com, points[i], values[i], messages[i]);
        cts.push(ct);
    }

    cts
}

/// Vector Decryption.
pub fn vec_decrypt<E: Pairing>(proofs: &[E::G1], cts: &[&Ciphertext<E>]) -> Vec<Vec<u8>> {
    let mut decrypted_messages = Vec::with_capacity(cts.len());

    for i in 0..cts.len() {
        let decrypted_message = decrypt::<E>(proofs[i], cts[i]);
        decrypted_messages.push(decrypted_message);
    }

    decrypted_messages
}
