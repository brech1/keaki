//! # Laconic OT
//!
//! This module contains the implementation of a Laconic Oblivious Transfer using we-kzg.

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_std::UniformRand;
use keaki::{
    pol_op::lagrange_interpolation,
    we::{WEError, WE},
};
use rand::thread_rng;
use std::time::Instant;

/// Type alias for the plaintext tuple
pub type PlaintextTuple = (Vec<u8>, Vec<u8>);
/// Type alias for a single ciphertext
pub type Ciphertext<E> = (<E as Pairing>::G2, Vec<u8>);
/// Type alias for the ciphertext tuple
pub type CiphertextTuple<E> = (Ciphertext<E>, Ciphertext<E>);

pub struct Receiver<E: Pairing> {
    we: WE<E>,
    boolean_choices: Vec<E::ScalarField>,
    commitment: E::G1,
    proofs: Vec<E::G1>, // New field to store precomputed proofs
}

impl<E: Pairing> Receiver<E> {
    pub fn setup(we: WE<E>, boolean_choices: Vec<E::ScalarField>) -> Self {
        // pad with random evaluations to blind polynomial
        let ck_len = we.kzg().g1_pow().len();
        let pad_len = ck_len - boolean_choices.len();
        let pad = (0..pad_len)
            .map(|_| E::ScalarField::rand(&mut thread_rng()))
            .collect();
        let evaluations = [boolean_choices.clone(), pad].concat();

        // interpolate polynomial
        let interpolation_start = Instant::now();
        let points: Vec<E::ScalarField> = (0..ck_len)
            .map(|i| E::ScalarField::from(i as u64))
            .collect();
        let selection_polynomial = lagrange_interpolation::<E>(&points, &evaluations).unwrap();
        let interpolation_time = interpolation_start.elapsed();
        println!("Interpolation time: {:?}", interpolation_time);

        // commit to polynomial
        let commitment_start = Instant::now();
        let commitment = we.kzg().commit(&selection_polynomial).unwrap();
        let commitment_time = commitment_start.elapsed();
        println!("Commitment time: {:?}", commitment_time);

        // Generate proofs for each index
        let proof_gen_start = Instant::now();
        let proofs: Vec<E::G1> = (0..boolean_choices.len())
            .map(|index| {
                we.kzg()
                    .open(&selection_polynomial, &E::ScalarField::from(index as u64))
                    .unwrap()
            })
            .collect();
        let proof_gen_time = proof_gen_start.elapsed();
        println!("Proof generation time: {:?}", proof_gen_time);

        Self {
            we,
            boolean_choices,
            commitment,
            proofs, // Store the precomputed proofs
        }
    }

    pub fn receive(
        &self,
        encrypted_keys: Vec<CiphertextTuple<E>>,
    ) -> Result<Vec<Vec<u8>>, WEError> {
        let mut decrypted_messages = Vec::new();
        let mut total_decryption_time = std::time::Duration::new(0, 0);

        for (index, encrypted_key) in encrypted_keys.iter().enumerate() {
            // Use the precomputed proof
            let proof = self.proofs[index];

            // chose ciphertext to decrypt based on boolean choice
            let (key_ct, msg_ct) = if self.boolean_choices[index] == E::ScalarField::ZERO {
                encrypted_key.0.clone()
            } else {
                encrypted_key.1.clone()
            };

            // decrypt message
            let decryption_start = Instant::now();
            let decrypted_message = self.we.decrypt_single(proof, key_ct, &msg_ct).unwrap();
            total_decryption_time += decryption_start.elapsed();
            decrypted_messages.push(decrypted_message);
        }

        // Remove the total_proof_gen_time print statement
        println!("Total decryption time: {:?}", total_decryption_time);

        Ok(decrypted_messages)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sender<E: Pairing> {
    we: WE<E>,
}

impl<E: Pairing> Sender<E> {
    pub fn setup(we: WE<E>) -> Self {
        Self { we }
    }

    pub fn send(
        &self,
        circuit_keys: Vec<PlaintextTuple>,
        commitment: E::G1,
    ) -> Result<Vec<CiphertextTuple<E>>, WEError> {
        let mut encrypted_messages = Vec::new();
        let encryption_start = Instant::now();

        for (index, value) in circuit_keys.iter().enumerate() {
            let enc_message_0 = self.we.encrypt_single(
                commitment,
                E::ScalarField::from(index as u64),
                E::ScalarField::ZERO,
                &value.0,
            )?;

            let enc_message_1 = self.we.encrypt_single(
                commitment,
                E::ScalarField::from(index as u64),
                E::ScalarField::ONE,
                &value.1,
            )?;

            encrypted_messages.push((enc_message_0, enc_message_1));
        }

        let encryption_time = encryption_start.elapsed();
        println!("Encryption time: {:?}", encryption_time);

        Ok(encrypted_messages)
    }
}

#[cfg(test)]
mod new_laconic_ot_tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{test_rng, UniformRand};
    use keaki::{kzg::KZG, we::WE};
    use rand::Rng;

    const MAX_DEGREE: usize = 32;
    const NUM_OT_VALUES: usize = 32;

    #[test]
    fn test_laconic_ot() {
        // Setup KZG commitment scheme
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let kzg = KZG::<Bls12_381>::setup(secret, MAX_DEGREE);
        let we: WE<Bls12_381> = WE::new(kzg);

        // --------------------
        // ----- Receiver -----
        // --------------------

        // Receiver's boolean choices
        let boolean_choices: Vec<Fr> = (0..NUM_OT_VALUES)
            .map(|_| if rng.gen_bool(0.5) { Fr::ONE } else { Fr::ZERO })
            .collect();

        let receiver_setup_start = Instant::now();
        let receiver = Receiver::setup(we.clone(), boolean_choices.clone());
        let receiver_setup_time = receiver_setup_start.elapsed();
        println!("Receiver setup time: {:?}\n", receiver_setup_time);

        // --------------------
        // ------ Sender ------
        // --------------------

        // Set up pairs of circuit keys for receiver to choose from
        const VALUE_LENGTH: usize = 32;
        let circuit_keys: Vec<PlaintextTuple> = (0..NUM_OT_VALUES)
            .map(|_| {
                (
                    (0..VALUE_LENGTH).map(|_| rng.gen()).collect(),
                    (0..VALUE_LENGTH).map(|_| rng.gen()).collect(),
                )
            })
            .collect();
        let sender = Sender::setup(we);

        // Encrypt the pairs of circuit keys using receiver's commitment
        let sender_send_start = Instant::now();
        let encrypted_messages = sender
            .send(circuit_keys.clone(), receiver.commitment)
            .unwrap();
        let sender_send_time = sender_send_start.elapsed();
        println!("Sender send time: {:?}\n", sender_send_time);

        // --------------------
        // ----- Receiver -----
        // --------------------

        // Decrypt the pairs of ciphertexts using the receiver's boolean choice
        let receiver_receive_start = Instant::now();
        let decrypted_messages = receiver.receive(encrypted_messages).unwrap();
        let receiver_receive_time = receiver_receive_start.elapsed();
        println!("Receiver receive time: {:?}\n", receiver_receive_time);

        // Verify correctness of decrypted messages
        for (i, decrypted_message) in decrypted_messages.iter().enumerate() {
            let expected_value = if boolean_choices[i] == Fr::ZERO {
                &circuit_keys[i].0
            } else {
                &circuit_keys[i].1
            };

            assert_eq!(decrypted_message, expected_value, "Mismatch at index {}", i);
        }
    }
}
