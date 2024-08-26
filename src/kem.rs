//! KEM Module
//!
//! This module contains the implementation of an Extractable Witness Key Encapsulation Mechanism (KEM).

use crate::kzg::KZG;
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{self};
use ark_std::UniformRand;
use blake3::hash;
use rand::thread_rng;
use std::ops::Mul;

/// Key Encapsulation Mechanism struct.
pub struct KEM<E: Pairing> {
    kzg: KZG<E>,
}

impl<E: Pairing> KEM<E> {
    /// Creates a new KEM instance.
    pub fn new(kzg: KZG<E>) -> Self {
        Self { kzg }
    }

    /// Encapsulation method.
    /// Returns the key and a ciphertext.
    pub fn encapsulation(
        &self,
        commitment: E::G1,
        point: E::ScalarField,
        value: E::ScalarField,
    ) -> (E::G2, [u8; 32]) {
        let mut rng = thread_rng();
        let r = E::ScalarField::rand(&mut rng);

        // [beta]_1
        let value_in_g1: E::G1 = self.kzg.g1_gen().mul(value);

        // (com - [beta]_1)
        let com_beta = commitment - value_in_g1;

        // Calculate secret
        // s = e(r * (com - [beta]_1), g2)
        let secret = E::pairing(com_beta.mul(r), self.kzg.g2_gen());
        let mut secret_bytes = Vec::<u8>::new();
        secret.serialize_uncompressed(&mut secret_bytes).unwrap();

        // Calculate ciphertext
        // ct = r([tau]_2 - [alpha]_2)
        let tau_alpha: E::G2 = self.kzg.tau_g2() - self.kzg.g2_gen().mul(point);
        let ciphertext: E::G2 = tau_alpha.mul(r);

        // Get the key
        // k = H(s)
        let key = hash(&secret_bytes);
        let key_bytes = *key.as_bytes();

        (ciphertext, key_bytes)
    }

    /// Decapsulation method.
    /// Returns the key.
    pub fn decapsulation(&self, proof: E::G1, ciphertext: E::G2) -> [u8; 32] {
        // Calculate secret
        // s = e(proof, ct)
        let secret = E::pairing(proof, ciphertext);

        let mut secret_bytes = Vec::<u8>::new();
        secret.serialize_uncompressed(&mut secret_bytes).unwrap();

        // Get the key
        // k = H(s)
        let key = hash(&secret_bytes);
        let key_bytes = *key.as_bytes();

        key_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::evaluate_polynomial;
    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_encapsulation_decapsulation() {
        let rng = &mut test_rng();
        let g1_gen = G1Projective::rand(rng);
        let g2_gen = G2Projective::rand(rng);
        let secret = Fr::rand(rng);
        let max_degree = 10;
        let point: Fr = Fr::rand(rng);
        let kzg: KZG<Bls12_381> = KZG::setup(g1_gen, g2_gen, max_degree, secret);
        let kem: KEM<Bls12_381> = KEM::new(kzg);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = vec![
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ];
        let val = evaluate_polynomial::<Bls12_381>(&p, &point);
        let commitment = kem.kzg.commit(&p).unwrap();

        // Encapsulate
        let (ciphertext, encapsulation_key) = kem.encapsulation(commitment, point, val);

        // Decapsulate
        let proof = kem.kzg.open(&p, &point).unwrap();
        let decapsulated_key = kem.decapsulation(proof, ciphertext);

        assert_eq!(encapsulation_key, decapsulated_key);
    }

    #[test]
    fn test_decapsulation_with_invalid_proof() {
        let rng = &mut test_rng();
        let g1_gen = G1Projective::rand(rng);
        let g2_gen = G2Projective::rand(rng);
        let secret = Fr::rand(rng);
        let max_degree = 10;
        let point: Fr = Fr::rand(rng);
        let kzg: KZG<Bls12_381> = KZG::setup(g1_gen, g2_gen, max_degree, secret);
        let kem: KEM<Bls12_381> = KEM::new(kzg);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = vec![
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ];
        let val = evaluate_polynomial::<Bls12_381>(&p, &point);
        let commitment = kem.kzg.commit(&p).unwrap();

        // Encapsulate
        let (ciphertext, encapsulation_key) = kem.encapsulation(commitment, point, val);

        // Generate an invalid proof (e.g., for a different point)
        let wrong_point: Fr = Fr::rand(rng);
        let invalid_proof = kem.kzg.open(&p, &wrong_point).unwrap();

        // Attempt to decapsulate with the invalid proof
        let decapsulated_key = kem.decapsulation(invalid_proof, ciphertext);

        // The keys should not match
        assert_ne!(encapsulation_key, decapsulated_key);
    }

    #[test]
    fn test_decapsulation_with_invalid_ciphertext() {
        let rng = &mut test_rng();
        let g1_gen = G1Projective::rand(rng);
        let g2_gen = G2Projective::rand(rng);
        let secret = Fr::rand(rng);
        let max_degree = 10;
        let point: Fr = Fr::rand(rng);
        let kzg: KZG<Bls12_381> = KZG::setup(g1_gen, g2_gen, max_degree, secret);
        let kem: KEM<Bls12_381> = KEM::new(kzg);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = vec![
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ];
        let val = evaluate_polynomial::<Bls12_381>(&p, &point);
        let commitment = kem.kzg.commit(&p).unwrap();

        // Encapsulate
        let (ciphertext, encapsulation_key) = kem.encapsulation(commitment, point, val);

        // Generate an invalid ciphertext (e.g., by using a different random value)
        let invalid_ciphertext = ciphertext.mul(Fr::rand(rng));

        // Attempt to decapsulate with the invalid ciphertext
        let proof = kem.kzg.open(&p, &point).unwrap();
        let decapsulated_key = kem.decapsulation(proof, invalid_ciphertext);

        // The keys should not match
        assert_ne!(encapsulation_key, decapsulated_key);
    }

    #[test]
    fn test_decapsulation_with_mismatched_proof_and_ciphertext() {
        let rng = &mut test_rng();
        let g1_gen = G1Projective::rand(rng);
        let g2_gen = G2Projective::rand(rng);
        let secret = Fr::rand(rng);
        let max_degree = 10;
        let point1: Fr = Fr::rand(rng);
        let point2: Fr = Fr::rand(rng);
        let kzg: KZG<Bls12_381> = KZG::setup(g1_gen, g2_gen, max_degree, secret);
        let kem: KEM<Bls12_381> = KEM::new(kzg);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = vec![
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ];
        let val1 = evaluate_polynomial::<Bls12_381>(&p, &point1);
        let commitment = kem.kzg.commit(&p).unwrap();

        // Encapsulate with point1
        let (ciphertext1, encapsulation_key1) = kem.encapsulation(commitment, point1, val1);

        // Generate proof for point2
        let proof2 = kem.kzg.open(&p, &point2).unwrap();

        // Attempt to decapsulate with a mismatched proof and ciphertext
        let decapsulated_key = kem.decapsulation(proof2, ciphertext1);

        // The keys should not match
        assert_ne!(encapsulation_key1, decapsulated_key);
    }
}
