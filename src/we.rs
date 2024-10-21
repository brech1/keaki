//! # Extractable Witness Encryption
//!
//! This module contains the implementation of an Extractable Witness Encryption from an Extractable Witness KEM.

use crate::{
    kem::{self, KEMError},
    kzg::KZG,
};
use ark_ec::pairing::Pairing;
use ark_std::vec::Vec;
use thiserror::Error;

/// Ciphertext type alias.
pub type Ciphertext<E> = (<E as Pairing>::G2, Vec<u8>);

/// Extractable Witness Encryption struct.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WE<E: Pairing> {
    kzg: KZG<E>,
}

impl<E: Pairing> WE<E> {
    /// Create a new instance.
    pub fn new(kzg: KZG<E>) -> Self {
        Self { kzg }
    }

    /// Encrypts a message using a commitment, point, and value.
    /// Returns two ciphertexts:
    /// - `key_ct`: used to generate the decryption key.
    /// - `msg_ct`: the encrypted message.
    pub fn encrypt(
        &self,
        com: E::G1,
        point: E::ScalarField,
        value: E::ScalarField,
        msg: &[u8],
    ) -> Result<Ciphertext<E>, WEError> {
        // Generate a key and the corresponding key ciphertext
        // (ct_1, k) <- Encap(x)
        let (key_ct, mut key_stream) = kem::encapsulate(&self.kzg, com, point, value)?;

        // ct_2 <- Enc(k, m)
        let mut msg_ct = vec![0u8; msg.len()];
        key_stream.fill(&mut msg_ct);
        for i in 0..msg.len() {
            msg_ct[i] ^= msg[i];
        }

        // (ct_1, ct_2)
        Ok((key_ct, msg_ct))
    }

    /// Decrypts a ciphertext with a proof.
    /// Returns the decrypted message.
    pub fn decrypt(&self, proof: E::G1, key_ct: E::G2, msg_ct: &[u8]) -> Result<Vec<u8>, WEError> {
        // k = Decap(w, ct_1)
        let mut key_stream = kem::decapsulate::<E>(proof, key_ct)?;

        // m = Dec(k, ct_2)
        let mut msg = vec![0u8; msg_ct.len()];
        key_stream.fill(&mut msg);
        for i in 0..msg_ct.len() {
            msg[i] ^= msg_ct[i];
        }

        Ok(msg)
    }

    /// Returns the KZG instance.
    pub fn kzg(&self) -> &KZG<E> {
        &self.kzg
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum WEError {
    #[error("Key Encapsulation Error {0}")]
    KEMError(KEMError),
}

impl From<KEMError> for WEError {
    fn from(error: KEMError) -> Self {
        WEError::KEMError(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::{rand::Rng, test_rng, UniformRand};

    fn setup_kzg(rng: &mut impl Rng) -> KZG<Bls12_381> {
        let secret = Fr::rand(rng);
        KZG::<Bls12_381>::setup(secret, 10)
    }

    #[test]
    fn test_encrypt() {
        let rng = &mut test_rng();
        let kzg = setup_kzg(rng);
        let we: WE<Bls12_381> = WE::new(kzg);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let point: Fr = Fr::rand(rng);
        let val = p.evaluate(&point);
        let commitment = we.kzg().commit(&p).unwrap();

        let msg = b"helloworld";

        let (key_ct, msg_ct) = we.encrypt(commitment, point, val, msg).unwrap();

        let proof = we.kzg().open(&p, &point).unwrap();

        let decrypted_msg = we.decrypt(proof, key_ct, &msg_ct).unwrap();

        assert_eq!(msg.to_vec(), decrypted_msg);
    }

    #[test]
    fn test_decrypt_invalid_proof() {
        let rng = &mut test_rng();
        let kzg = setup_kzg(rng);
        let we: WE<Bls12_381> = WE::new(kzg);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let point: Fr = Fr::rand(rng);
        let val = p.evaluate(&point);
        let commitment = we.kzg().commit(&p).unwrap();

        let msg = b"helloworld";
        let (key_ct, msg_ct) = we.encrypt(commitment, point, val, msg).unwrap();

        let wrong_point: Fr = Fr::rand(rng);
        let invalid_proof = we.kzg().open(&p, &wrong_point).unwrap();

        let decrypted_msg = we.decrypt(invalid_proof, key_ct, &msg_ct).unwrap();

        assert_ne!(msg.to_vec(), decrypted_msg);
    }
}
