//! # Laconic OT
//!
//! This module contains the implementation of a Laconic Oblivious Transfer using we-kzg.

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use keaki::{
    vec::{VectorWE, VectorWEError},
    we::Ciphertext,
};
use std::time::Instant;

/// Type alias for the plaintext tuple
pub type PlaintextTuple = (Vec<u8>, Vec<u8>);
/// Type alias for the ciphertext tuple
pub type CiphertextTuple<E> = (Ciphertext<E>, Ciphertext<E>);

pub struct Receiver<E: Pairing> {
    /// Receiver's choices
    boolean_choices: Vec<E::ScalarField>,
    /// Polynomial commitment
    commitment: E::G1,
    /// Precomputed proofs
    proofs: Vec<E::G1>,
}

impl<E: Pairing> Receiver<E> {
    pub fn new(vec_we: &VectorWE<E>, boolean_choices: Vec<E::ScalarField>) -> Self {
        let commitment_start = Instant::now();
        let (commitment, proofs) = vec_we.commit(&boolean_choices).unwrap();
        let commitment_time = commitment_start.elapsed();
        println!("Commitment time: {:?}", commitment_time);

        Self {
            boolean_choices,
            commitment,
            proofs,
        }
    }

    pub fn receive(
        &self,
        vec_we: &VectorWE<E>,
        ct_pairs: Vec<CiphertextTuple<E>>,
    ) -> Result<Vec<Vec<u8>>, VectorWEError> {
        let mut decrypted_messages = Vec::new();
        let mut total_decryption_time = std::time::Duration::new(0, 0);

        for (index, ct_pair) in ct_pairs.iter().enumerate() {
            // Use the precomputed proof
            let proof = self.proofs[index];

            // chose ciphertext to decrypt based on boolean choice
            let chosen_ct = if self.boolean_choices[index] == E::ScalarField::ZERO {
                ct_pair.0.clone()
            } else {
                ct_pair.1.clone()
            };

            // decrypt message
            let decryption_start = Instant::now();
            let decrypted_message = vec_we.decrypt(proof, chosen_ct);
            total_decryption_time += decryption_start.elapsed();
            decrypted_messages.push(decrypted_message);
        }

        // Remove the total_proof_gen_time print statement
        println!("Total decryption time: {:?}", total_decryption_time);

        Ok(decrypted_messages)
    }
}

pub struct Sender<E: Pairing> {
    commitment: E::G1,
}

impl<E: Pairing> Sender<E> {
    pub fn new(commitment: E::G1) -> Self {
        Self { commitment }
    }

    pub fn send(
        &self,
        vec_we: &VectorWE<E>,
        circuit_keys: &[PlaintextTuple],
    ) -> Result<Vec<CiphertextTuple<E>>, VectorWEError> {
        let mut encrypted_messages = Vec::with_capacity(circuit_keys.len());
        let encryption_start = Instant::now();

        for (index, value) in circuit_keys.iter().enumerate() {
            encrypted_messages.push((
                vec_we.encrypt(self.commitment, index, E::ScalarField::ZERO, &value.0),
                vec_we.encrypt(self.commitment, index, E::ScalarField::ONE, &value.1),
            ));
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
    use ark_std::{rand::Rng, test_rng, UniformRand};
    use keaki::{kzg::KZG, vec::VectorWE};

    const MAX_DEGREE: usize = 32;
    const NUM_OT_VALUES: usize = 32;
    const VALUE_LENGTH: usize = 32;

    #[test]
    fn test_laconic_ot() {
        // Setup KZG commitment scheme
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let kzg = KZG::<Bls12_381>::setup(secret, MAX_DEGREE);
        let vec_we: VectorWE<Bls12_381> = VectorWE::new(kzg);

        // --------------------
        // ----- Receiver -----
        // --------------------

        // Receiver's boolean choices
        let boolean_choices: Vec<Fr> = (0..NUM_OT_VALUES)
            .map(|_| if rng.gen_bool(0.5) { Fr::ONE } else { Fr::ZERO })
            .collect();

        let receiver_setup_start = Instant::now();
        let receiver = Receiver::new(&vec_we, boolean_choices.clone());
        let receiver_setup_time = receiver_setup_start.elapsed();
        println!("Receiver setup time: {:?}\n", receiver_setup_time);

        // --------------------
        // ------ Sender ------
        // --------------------

        // Set up pairs of circuit keys for receiver to choose from
        let circuit_keys: Vec<PlaintextTuple> = (0..NUM_OT_VALUES)
            .map(|_| {
                (
                    (0..VALUE_LENGTH).map(|_| rng.gen()).collect(),
                    (0..VALUE_LENGTH).map(|_| rng.gen()).collect(),
                )
            })
            .collect();
        let sender = Sender::new(receiver.commitment);

        // Encrypt the pairs of circuit keys using receiver's commitment
        let sender_send_start = Instant::now();
        let encrypted_messages = sender.send(&vec_we, &circuit_keys).unwrap();
        let sender_send_time = sender_send_start.elapsed();
        println!("Sender send time: {:?}\n", sender_send_time);

        // --------------------
        // ----- Receiver -----
        // --------------------

        // Decrypt the pairs of ciphertexts using the receiver's boolean choice
        let receiver_receive_start = Instant::now();
        let decrypted_messages = receiver.receive(&vec_we, encrypted_messages).unwrap();
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
