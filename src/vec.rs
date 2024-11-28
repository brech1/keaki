//! # Vector
//!
//! This module provides an abstraction to enhance performance when dealing with vectors.

use crate::{
    kzg::{commit, open_fk, KZGSetup},
    we::{decrypt, encrypt, Ciphertext},
};
use ark_ec::pairing::Pairing;
use ark_poly::{
    domain::EvaluationDomain, polynomial::univariate::DensePolynomial, DenseUVPolynomial,
};
use ark_std::UniformRand;

/// Commit to a vector of values.
/// Returns the commitment and the proofs for each index.
pub fn vec_commit<E: Pairing>(
    rng: &mut impl rand::Rng,
    kzg_setup: &KZGSetup<E>,
    vec: &[E::ScalarField],
) -> Result<(E::G1, Vec<E::G1>), &'static str> {
    // Pad with a random value.
    // This is necessary since the commitment could leak information about the vector.
    let r = E::ScalarField::rand(rng);

    let mut padded_vec = Vec::with_capacity(vec.len() + 1);
    padded_vec.extend_from_slice(vec);
    padded_vec.push(r);

    // Transform the vector into a polynomial in coefficient form
    let p_coeff = kzg_setup.domain().ifft(&padded_vec);

    // Calculate proofs for each index
    let proofs = open_fk(kzg_setup, &p_coeff).unwrap();

    // Construct the dense polynomial from the coefficients
    let p_dense = DensePolynomial::from_coefficients_vec(p_coeff);

    // Commit
    let com = commit(kzg_setup, &p_dense).unwrap();

    Ok((com, proofs))
}

/// Vector Encryption
pub fn vec_encrypt<E: Pairing>(
    rng: &mut impl rand::Rng,
    kzg_setup: &KZGSetup<E>,
    com: E::G1,
    values: &[E::ScalarField],
    messages: &[&[u8]],
) -> Vec<Ciphertext<E>> {
    let len = messages.len();
    let mut cts = Vec::with_capacity(len);

    for ((&value, &message), element) in values
        .iter()
        .zip(messages.iter())
        .zip(&mut kzg_setup.domain().elements())
    {
        let ct = encrypt::<E>(rng, kzg_setup, com, element, value, message).unwrap();
        cts.push(ct);
    }

    cts
}

/// Vector Decryption
pub fn vec_decrypt<E: Pairing>(proofs: &[E::G1], cts: &[&Ciphertext<E>]) -> Vec<Vec<u8>> {
    let mut decrypted_messages = Vec::with_capacity(cts.len());

    for (proof, ct) in proofs.iter().zip(cts) {
        let decrypted_message = decrypt::<E>(*proof, ct).unwrap();
        decrypted_messages.push(decrypted_message);
    }

    decrypted_messages
}
