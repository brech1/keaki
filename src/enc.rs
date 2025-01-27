//! # Encryption
//!
//! This module provides functions for encrypting and decrypting messages based on the KEM.

use crate::{
    kem::{decapsulate, encapsulate},
    kzg::KZGSetup,
};
use ark_ec::pairing::Pairing;
use ark_std::vec::Vec;

/// Ciphertext type alias.
pub type Ciphertext<E> = (<E as Pairing>::G2, Vec<u8>);

/// Encrypts a message using a commitment, point, and value.
/// Returns two ciphertexts:
/// - `key_ct`: used to generate the decryption key.
/// - `msg_ct`: the encrypted message.
pub fn encrypt<E: Pairing>(
    rng: &mut impl rand::Rng,
    kzg_setup: &KZGSetup<E>,
    com: E::G1,
    point: E::ScalarField,
    value: E::ScalarField,
    msg: &[u8],
) -> Ciphertext<E> {
    // Generate a key and the corresponding key ciphertext
    // (ct_1, k) <- Encap(x)
    let (key_ct, key) = encapsulate::<E>(rng, kzg_setup, com, point, value, msg.len());

    // ct_2 <- Enc(k, m)
    let mut msg_ct = vec![0u8; msg.len()];
    msg_ct
        .iter_mut()
        .zip(key.iter().zip(msg.iter()))
        .for_each(|(out, (&k, &m))| *out = k ^ m);

    // (ct_1, ct_2)
    (key_ct, msg_ct)
}

/// Decrypts a ciphertext with a proof.
/// Returns the decrypted message.
pub fn decrypt<E: Pairing>(proof: E::G1, ct: &Ciphertext<E>) -> Vec<u8> {
    let mut key = decapsulate::<E>(proof, ct.0, ct.1.len());

    // Decrypt
    let msg: Vec<u8> = key
        .iter_mut()
        .zip(ct.1.iter())
        .map(|(k, &c)| *k ^ c)
        .collect();

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kzg::{commit, open, KZGSetup};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::{rand::Rng, test_rng, UniformRand};

    fn setup_kzg(rng: &mut impl Rng) -> KZGSetup<Bls12_381> {
        let secret = Fr::rand(rng);
        KZGSetup::<Bls12_381>::setup(secret, 10)
    }

    #[test]
    fn test_encrypt() {
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
        let val = p.evaluate(&point);
        let commitment = commit(&kzg_setup, &p).unwrap();

        let msg = b"helloworld";

        let ct = encrypt::<Bls12_381>(rng, &kzg_setup, commitment, point, val, msg);

        let proof = open(&kzg_setup, &p, &point).unwrap();

        let decrypted_msg = decrypt::<Bls12_381>(proof, &ct);

        assert_eq!(msg.to_vec(), decrypted_msg);
    }

    #[test]
    fn test_decrypt_invalid_proof() {
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
        let val = p.evaluate(&point);
        let commitment = commit(&kzg_setup, &p).unwrap();
        let msg = b"helloworld";
        let ct = encrypt::<Bls12_381>(rng, &kzg_setup, commitment, point, val, msg);

        let wrong_point: Fr = Fr::rand(rng);
        let invalid_proof = open(&kzg_setup, &p, &wrong_point).unwrap();

        let decrypted_msg = decrypt::<Bls12_381>(invalid_proof, &ct);

        assert_ne!(msg.to_vec(), decrypted_msg);
    }
}
