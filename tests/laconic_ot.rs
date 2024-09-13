//! # Laconic OT
//!
//! This module contains the implementation of a Laconic Oblivious Transfer using we-kzg.

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use keaki::{
    kzg::{KZGError, KZG},
    pol_op::evaluate_polynomial,
    we::{WEError, WE},
};

pub const SUCCESSFUL_DECRYPTION_PAD: usize = 32;
pub const SUCCESSFUL_DECRYPTION: &[u8] = &[0u8; SUCCESSFUL_DECRYPTION_PAD];

pub struct LaconicOT<E: Pairing> {
    we: WE<E>,
}

impl<E: Pairing> LaconicOT<E> {
    pub fn new(we: WE<E>) -> Self {
        Self { we }
    }

    pub fn we(&self) -> &WE<E> {
        &self.we
    }
}

pub trait Receiver<E: Pairing> {
    /// Commits to a selection polynomial.
    /// - `kzg`: the KZG instance.
    /// - `selection`: the selection index.
    fn commit(&self, kzg: &KZG<E>, selection: usize) -> Result<E::G1, KZGError> {
        let max_degree = kzg.max_degree();
        let mut selection_polynomial = vec![E::ScalarField::ZERO; max_degree];
        selection_polynomial[selection] = E::ScalarField::ONE;

        kzg.commit(&selection_polynomial)
    }

    /// Generates a proof for a given point.
    /// - `kzg`: the KZG instance.
    /// - `selection`: the selection index.
    fn generate_proof(&self, kzg: &KZG<E>, selection: usize) -> Result<E::G1, KZGError> {
        let max_degree = kzg.max_degree();
        let mut selection_polynomial = vec![E::ScalarField::ZERO; max_degree];
        selection_polynomial[selection] = E::ScalarField::ONE;

        kzg.open(
            &selection_polynomial,
            &E::ScalarField::from(selection as u64),
        )
    }

    /// Decrypts the sender's set of ciphertexts.
    /// - `we`: the WE instance.
    /// - `kzg`: the KZG instance.
    /// - `selection`: the selection index.
    /// - `encrypted_messages`: the sender's set of ciphertexts.
    fn decrypt(
        &self,
        we: &WE<E>,
        selection: usize,
        encrypted_messages: Vec<(E::G2, Vec<u8>)>,
    ) -> Result<Vec<Vec<u8>>, WEError> {
        let proof = self.generate_proof(we.kzg(), selection).unwrap();

        let mut decrypted_messages = Vec::new();

        for encrypted_message in encrypted_messages {
            let (key_ct, msg_ct) = encrypted_message;

            let decrypted_msg = we.decrypt_single(proof, key_ct, &msg_ct)?;
            decrypted_messages.push(decrypted_msg);
        }

        Ok(decrypted_messages)
    }
}

pub trait Sender<E: Pairing> {
    /// Encrypts a set of values for a given commitment.
    /// - `we`: the WE instance.
    /// - `values`: the list of values.
    /// - `commitment`: the commitment to the selection polynomial.
    fn encrypt(
        &self,
        we: &WE<E>,
        values: &[&[u8]],
        commitment: E::G1,
    ) -> Result<Vec<(E::G2, Vec<u8>)>, WEError> {
        let message_pad = Vec::from(SUCCESSFUL_DECRYPTION);

        let mut encrypted_messages = Vec::new();
        for (index, &value) in values.iter().enumerate() {
            let mut message = message_pad.clone();
            message.extend(value);

            // Evaluate the polynomial
            let mut selection_polynomial = vec![E::ScalarField::ZERO; we.kzg().max_degree()];
            selection_polynomial[index] = E::ScalarField::ONE;
            let value = evaluate_polynomial::<E>(
                &selection_polynomial,
                &E::ScalarField::from(index as u64),
            );

            let enc_message = we.encrypt_single(
                commitment,
                E::ScalarField::from(index as u64),
                value,
                &message,
            )?;

            encrypted_messages.push(enc_message);
        }

        Ok(encrypted_messages)
    }
}

#[cfg(test)]
mod laconic_ot_tests {
    use super::*;
    use ark_bls12_381::{
        g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
        g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
        Bls12_381, Fr, G1Affine, G2Affine,
    };
    use ark_std::{test_rng, UniformRand};
    use keaki::{kzg::KZG, we::WE};
    use rand::Rng;

    const MAX_DEGREE: usize = 4;

    /// Setups the KZG instance.
    fn setup_kzg() -> KZG<Bls12_381> {
        let rng = &mut test_rng();
        let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
        let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);
        let secret = Fr::rand(rng);

        KZG::setup(g1_generator.into(), g2_generator.into(), MAX_DEGREE, secret)
    }

    #[test]
    fn test_laconic_ot() {
        let rng = &mut test_rng();
        let kzg = setup_kzg();
        let we: WE<Bls12_381> = WE::new(kzg);
        let laconic_ot = LaconicOT::new(we);

        // --------------------
        // ----- Receiver -----
        // --------------------

        // Implement the Receiver trait
        impl<E: Pairing> Receiver<E> for LaconicOT<E> {}

        // Receiver makes a random selection and commits to it
        let selection: usize = rng.gen_range(0..MAX_DEGREE);
        let commitment = laconic_ot.commit(laconic_ot.we().kzg(), selection).unwrap();

        // --------------------
        // ------ Sender ------
        // --------------------

        // Implement the Sender trait
        impl<E: Pairing> Sender<E> for LaconicOT<E> {}

        // Generate 4 random values
        const VALUE_LENGTH: usize = 32;
        let mut values: Vec<&[u8]> = Vec::with_capacity(MAX_DEGREE);

        for _ in 0..MAX_DEGREE {
            let mut value: Vec<u8> = Vec::with_capacity(VALUE_LENGTH);

            for _ in 0..VALUE_LENGTH {
                let val: u8 = rng.gen();

                value.push(val);
            }

            values.push(value.leak());
        }

        // Sender encrypts the values
        let encrypted_messages = laconic_ot
            .encrypt(laconic_ot.we(), &values, commitment)
            .unwrap();

        // --------------------
        // ----- Receiver -----
        // --------------------

        // Receiver decrypts the messages
        let decrypted_messages = laconic_ot
            .decrypt(laconic_ot.we(), selection, encrypted_messages)
            .unwrap();

        let mut decrypted_values = Vec::new();
        for message in decrypted_messages {
            // Assert message length
            assert_eq!(message.len(), SUCCESSFUL_DECRYPTION_PAD + VALUE_LENGTH);

            if message.starts_with(SUCCESSFUL_DECRYPTION) {
                let value: Vec<u8> = message[SUCCESSFUL_DECRYPTION.len()..].to_vec();

                decrypted_values.push(value);
            }
        }

        // Assert that the receiver can only decrypt the message corresponding to the selection
        assert_eq!(decrypted_values.len(), 1);

        // Assert that the decrypted value is the same as the value at the selection index from the sender
        assert_eq!(decrypted_values[0], values[selection]);
    }
}
