//! # Laconic OT
//!
//! This module contains the implementation of a Laconic Oblivious Transfer using we-kzg.

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use keaki::{
    kzg::KZGSetup,
    vec::{vec_commit, vec_decrypt, vec_encrypt},
    we::Ciphertext,
};
use std::time::Instant;

/// Type alias for the plaintext tuple
pub type PlaintextTuple = (Vec<u8>, Vec<u8>);
/// Type alias for the ciphertext tuple
pub type CiphertextTuple<E> = (Ciphertext<E>, Ciphertext<E>);

pub struct Receiver<E: Pairing> {
    /// Receiver's choices
    choices: Vec<E::ScalarField>,
    /// Commitment
    commitment: E::G1,
    /// Precomputed proofs
    proofs: Vec<E::G1>,
}

impl<E: Pairing> Receiver<E> {
    pub fn new(
        kzg_setup: KZGSetup<E>,
        rng: &mut impl rand::Rng,
        choices: Vec<E::ScalarField>,
    ) -> Self {
        let (commitment, proofs) = vec_commit(rng, &kzg_setup, &choices).unwrap();

        Self {
            choices,
            commitment,
            proofs,
        }
    }

    pub fn receive(&self, ct_pairs: &[CiphertextTuple<E>]) -> Result<Vec<Vec<u8>>, &'static str> {
        let mut chosen_cts = Vec::with_capacity(ct_pairs.len());

        for (index, ct_pair) in ct_pairs.iter().enumerate() {
            chosen_cts.push(if self.choices[index] == E::ScalarField::ZERO {
                &ct_pair.0
            } else {
                &ct_pair.1
            });
        }

        let decrypted_messages = vec_decrypt::<E>(&self.proofs, &chosen_cts);

        Ok(decrypted_messages)
    }
}

pub struct Sender<E: Pairing> {
    /// KZG Setup
    kzg_setup: KZGSetup<E>,
    /// Commitment
    commitment: E::G1,
}

impl<E: Pairing> Sender<E> {
    pub fn new(kzg_setup: KZGSetup<E>, commitment: E::G1) -> Self {
        Self {
            kzg_setup,
            commitment,
        }
    }

    pub fn send(
        &self,
        rng: &mut impl rand::Rng,
        private_set: &[PlaintextTuple],
    ) -> Result<Vec<CiphertextTuple<E>>, &'static str> {
        let len = private_set.len();

        let mut values = Vec::with_capacity(2 * len);
        let mut messages = Vec::with_capacity(2 * len);

        for &(ref msg_zero, ref msg_one) in private_set {
            values.push(E::ScalarField::ZERO);
            values.push(E::ScalarField::ONE);

            messages.push(msg_zero.as_slice());
            messages.push(msg_one.as_slice());
        }

        // Encrypt all messages in a single call
        let cts = vec_encrypt::<E>(rng, &self.kzg_setup, self.commitment, &values, &messages);

        // Combine the ciphertexts into tuples
        let mut encrypted_messages = Vec::with_capacity(len);
        for i in 0..len {
            let ct_zero = cts[2 * i].clone();
            let ct_one = cts[2 * i + 1].clone();
            encrypted_messages.push((ct_zero, ct_one));
        }

        Ok(encrypted_messages)
    }
}

#[cfg(test)]
mod new_laconic_ot_tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{rand::Rng, test_rng, UniformRand};

    const MAX_DEGREE: usize = 32;
    const N_CHOICES: usize = 32;
    const VALUE_LENGTH: usize = 32;

    #[test]
    fn test_laconic_ot() {
        // Setup KZG commitment scheme
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let kzg = KZGSetup::<Bls12_381>::setup(secret, MAX_DEGREE);

        // --------------------
        // ----- Receiver -----
        // --------------------

        // In oblivious transfer, the receiver chooses a value from a set.
        let choices: Vec<Fr> = (0..N_CHOICES)
            .map(|_| if rng.gen_bool(0.5) { Fr::ONE } else { Fr::ZERO })
            .collect();

        let com_start = Instant::now();

        let receiver = Receiver::new(kzg.clone(), rng, choices.clone());

        let com_time = com_start.elapsed();
        println!("Commitment + proofs time: {:?}", com_time);

        // --------------------
        // ------ Sender ------
        // --------------------

        // The sender holds a private set, for which the receiver should only get to know a single value,
        // and the sender should not know which value the receiver chose.
        let private_set: Vec<PlaintextTuple> = (0..N_CHOICES)
            .map(|_| {
                (
                    (0..VALUE_LENGTH).map(|_| rng.gen()).collect(),
                    (0..VALUE_LENGTH).map(|_| rng.gen()).collect(),
                )
            })
            .collect();
        let sender = Sender::new(kzg.clone(), receiver.commitment.clone());

        // Encrypt the set using the receiver's commitment
        let sender_send_start = Instant::now();

        let encrypted_messages = sender.send(rng, &private_set).unwrap();

        let sender_send_time = sender_send_start.elapsed();
        println!("Sender send time: {:?}\n", sender_send_time);

        // --------------------
        // ----- Receiver -----
        // --------------------

        // Decrypt the pairs of ciphertexts using the receiver's boolean choice
        let receiver_receive_start = Instant::now();

        let decrypted_messages = receiver.receive(&encrypted_messages).unwrap();

        let receiver_receive_time = receiver_receive_start.elapsed();
        println!("Receiver receive time: {:?}\n", receiver_receive_time);

        // Verify correctness of decrypted messages
        for (i, decrypted_message) in decrypted_messages.iter().enumerate() {
            let expected_value = if choices[i] == Fr::ZERO {
                &private_set[i].0
            } else {
                &private_set[i].1
            };

            assert_eq!(decrypted_message, expected_value, "Mismatch at index {}", i);
        }
    }
}
