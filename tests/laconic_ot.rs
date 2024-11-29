//! # Laconic OT
//!
//! This module contains the implementation of a Laconic Oblivious Transfer using we-kzg.

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use keaki::{
    enc::Ciphertext,
    kzg::KZGSetup,
    vec::{vec_commit, vec_decrypt, vec_encrypt, PADDING_LEN},
};
use std::time::Instant;

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

    pub fn receive(
        &self,
        encrypted_sets: Vec<Vec<Ciphertext<E>>>,
    ) -> Result<Vec<Vec<u8>>, &'static str> {
        let n_choices = encrypted_sets[0].len();
        let mut chosen_cts = Vec::with_capacity(n_choices);

        for i in 0..n_choices {
            if self.choices[i] == E::ScalarField::ZERO {
                chosen_cts.push(&encrypted_sets[0][i]);
            } else {
                chosen_cts.push(&encrypted_sets[1][i]);
            }
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
        private_set: &[Vec<Vec<u8>>],
    ) -> Result<Vec<Vec<Ciphertext<E>>>, &'static str> {
        let n_values = private_set[0].len();
        let elements =
            Radix2EvaluationDomain::<<E as Pairing>::ScalarField>::new(n_values + PADDING_LEN)
                .unwrap()
                .elements()
                .collect::<Vec<E::ScalarField>>();

        let mut encrypted_messages = Vec::with_capacity(private_set.len());

        let data0: Vec<&[u8]> = private_set[0].iter().map(|v| v.as_slice()).collect();
        let ct_0 = vec_encrypt::<E>(
            rng,
            &self.kzg_setup,
            self.commitment,
            &elements,
            &vec![E::ScalarField::ZERO; n_values],
            &data0,
        );
        encrypted_messages.push(ct_0);

        let data1: Vec<&[u8]> = private_set[1].iter().map(|v| v.as_slice()).collect();
        let ct_1 = vec_encrypt::<E>(
            rng,
            &self.kzg_setup,
            self.commitment,
            &elements,
            &vec![E::ScalarField::ONE; n_values],
            &data1,
        );
        encrypted_messages.push(ct_1);

        Ok(encrypted_messages)
    }
}

#[cfg(test)]
mod laconic_ot_tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{rand::Rng, test_rng, UniformRand};

    const SETUP_DEGREE: usize = 16;
    const N_CHOICES: usize = 8;
    const CHOICE_CARDINALITY: usize = 2;
    const VALUE_BYTES: usize = 32;

    #[test]
    fn test_laconic_ot() {
        // Setup KZG commitment scheme
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let kzg = KZGSetup::<Bls12_381>::setup(secret, SETUP_DEGREE);

        // --------------------
        // ----- Receiver -----
        // --------------------

        // In oblivious transfer, the receiver chooses a value from a set.
        // In Laconic OT, the receiver chooses a value for each index.
        let choices: Vec<Fr> = (0..N_CHOICES)
            .map(|_| if rng.gen_bool(0.5) { Fr::ZERO } else { Fr::ONE })
            .collect();

        let com_start = Instant::now();

        let receiver = Receiver::new(kzg.clone(), rng, choices.clone());

        let com_time = com_start.elapsed();
        println!("Commitment + proofs time: {:?}", com_time);

        // --------------------
        // ------ Sender ------
        // --------------------

        // The sender holds a private set, for which the receiver should only get to know the selected values,
        // and the sender should not know which values the receiver chose.
        let mut private_set: Vec<Vec<Vec<u8>>> = Vec::new();
        for _ in 0..CHOICE_CARDINALITY {
            let mut choice_n = Vec::new();

            for _ in 0..N_CHOICES {
                let choice: Vec<u8> = (0..VALUE_BYTES).map(|_| rng.gen()).collect();
                choice_n.push(choice);
            }

            private_set.push(choice_n);
        }

        let sender = Sender::new(kzg.clone(), receiver.commitment.clone());

        // Encrypt the set using the receiver's commitment
        let sender_send_start = Instant::now();

        let encrypted_messages = sender.send(rng, &private_set).unwrap();

        let sender_send_time = sender_send_start.elapsed();
        println!("Sender encrypt time: {:?}\n", sender_send_time);

        // --------------------
        // ----- Receiver -----
        // --------------------

        // Decrypt the pairs of ciphertexts using the receiver's boolean choice
        let receiver_receive_start = Instant::now();

        let decrypted_messages = receiver.receive(encrypted_messages).unwrap();

        let receiver_receive_time = receiver_receive_start.elapsed();
        println!("Receiver decrypt time: {:?}\n", receiver_receive_time);

        // Verify correctness of decrypted messages
        for (i, decrypted_message) in decrypted_messages.iter().enumerate() {
            let expected_value = if choices[i] == Fr::ZERO {
                &private_set[0][i]
            } else {
                &private_set[1][i]
            };

            assert_eq!(decrypted_message, expected_value, "Mismatch at index {}", i);
        }
    }
}
