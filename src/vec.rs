//! # Vector
//!
//! This module contains a helper struct to use the extractable witness encryption scheme with vectors as polynomials.

use crate::{
    kem,
    kzg::{KZGError, KZG},
    we::{self, Ciphertext},
};
use ark_ec::pairing::Pairing;
use ark_poly::{
    domain::{EvaluationDomain, Radix2EvaluationDomain},
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial,
};
use ark_std::{rand::rngs::SmallRng, rand::SeedableRng, UniformRand};
use thiserror::Error;

/// Vector Witness Encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorWE<E: Pairing> {
    /// KZG commitment scheme
    kzg: KZG<E>,
    /// Evaluation domain
    domain_d: Radix2EvaluationDomain<<E as Pairing>::ScalarField>,
    /// Elements
    elements: Vec<E::ScalarField>,
}

impl<E: Pairing> VectorWE<E> {
    pub fn new(kzg: KZG<E>) -> Self {
        let domain_d = Radix2EvaluationDomain::new(kzg.g1_pow().len() - 1).unwrap();
        let elements = domain_d.elements().collect();

        Self {
            kzg,
            domain_d,
            elements,
        }
    }

    /// Commit to a vector of values.
    /// Returns the commitment and the proofs for each index.
    pub fn commit(&self, vec: &[E::ScalarField]) -> Result<(E::G1, Vec<E::G1>), VectorWEError> {
        // Pad with a random value.
        // This is necessary since the commitment could leak information about the vector.
        let mut rng = SmallRng::from_entropy();
        let r = E::ScalarField::rand(&mut rng);

        let mut values = vec.to_vec();
        values.push(r);

        // Transform the vector into a polynomial in coefficient form
        let p_coeff = self.domain_d.ifft(&values);

        // Calculate proofs for each index
        let proofs = self.kzg.open_fk(&p_coeff)?;

        // Construct the dense polynomial from the coefficients
        let p_dense = DensePolynomial::from_coefficients_vec(p_coeff);

        // Commit
        let com = self.kzg.commit(&p_dense)?;

        Ok((com, proofs))
    }

    /// Encrypt
    pub fn encrypt(
        &self,
        com: E::G1,
        index: usize,
        value: E::ScalarField,
        message: &[u8],
    ) -> Ciphertext<E> {
        we::encrypt::<E>(com, self.elements[index], value, message, self.kzg.tau_g2()).unwrap()
    }

    // Decrypt
    pub fn decrypt(&self, proof: E::G1, ct: Ciphertext<E>) -> Vec<u8> {
        we::decrypt::<E>(proof, ct).unwrap()
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VectorWEError {
    #[error("KZG error: {0}")]
    KZGError(KZGError),
    #[error("KEM error: {0}")]
    KEMError(kem::KEMError),
}

impl From<KZGError> for VectorWEError {
    fn from(err: KZGError) -> Self {
        VectorWEError::KZGError(err)
    }
}

impl From<kem::KEMError> for VectorWEError {
    fn from(err: kem::KEMError) -> Self {
        VectorWEError::KEMError(err)
    }
}
