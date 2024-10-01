// //! # Laconic OT
// //!
// //! This module contains the implementation of a Laconic Oblivious Transfer using we-kzg.

// use ark_ec::pairing::Pairing;
// use ark_ff::Field;
// use keaki::{
//     kzg::KZGError,
//     pol_op::evaluate_polynomial,
//     we::{WEError, WE},
// };

// pub const SUCCESSFUL_DECRYPTION_PAD: usize = 32;
// pub const SUCCESSFUL_DECRYPTION: &[u8] = &[0u8; SUCCESSFUL_DECRYPTION_PAD];

// /// Laconic OT Receiver struct.
// #[derive(Debug, Clone, Default, PartialEq, Eq)]
// pub struct OTReceiver<E: Pairing> {
//     we: WE<E>,
//     selection: usize,
// }

// impl<E: Pairing> OTReceiver<E> {
//     /// Creates a new instance.
//     pub fn new(we: WE<E>, selection: usize) -> Self {
//         Self { we, selection }
//     }

//     /// Commits to a selection polynomial.
//     pub fn commit(&self) -> Result<E::G1, KZGError> {
//         let selection_polynomial =
//             get_selection_polynomial::<E>(self.selection, self.we.kzg().max_degree());

//         self.we.kzg().commit(&selection_polynomial)
//     }

//     /// Decrypts the sender's set of ciphertexts.
//     pub fn decrypt(
//         &self,
//         encrypted_messages: Vec<(E::G2, Vec<u8>)>,
//     ) -> Result<Vec<Vec<u8>>, WEError> {
//         let selection_polynomial =
//             get_selection_polynomial::<E>(self.selection, self.we.kzg().max_degree());

//         // Generate proof
//         let proof = self
//             .we
//             .kzg()
//             .open(
//                 &selection_polynomial,
//                 &E::ScalarField::from(self.selection as u64),
//             )
//             .unwrap();

//         let mut decrypted_messages = Vec::new();
//         for encrypted_message in encrypted_messages {
//             let (key_ct, msg_ct) = encrypted_message;

//             let decrypted_msg = self.we.decrypt_single(proof, key_ct, &msg_ct)?;
//             decrypted_messages.push(decrypted_msg);
//         }

//         Ok(decrypted_messages)
//     }
// }

// /// Laconic OT Sender struct.
// #[derive(Debug, Clone, Default, PartialEq, Eq)]
// pub struct OTSender<E: Pairing> {
//     we: WE<E>,
// }

// impl<E: Pairing> OTSender<E> {
//     /// Creates a new instance.
//     pub fn new(we: WE<E>) -> Self {
//         Self { we }
//     }

//     /// Encrypts a set of values for a given commitment.
//     /// - `values`: the list of values.
//     /// - `commitment`: the commitment to the selection polynomial.
//     fn encrypt(
//         &self,
//         values: &[&[u8]],
//         commitment: E::G1,
//     ) -> Result<Vec<(E::G2, Vec<u8>)>, WEError> {
//         let message_pad = Vec::from(SUCCESSFUL_DECRYPTION);

//         let mut encrypted_messages = Vec::new();
//         for (index, &value) in values.iter().enumerate() {
//             let mut message = message_pad.clone();
//             message.extend(value);

//             // Evaluate the polynomial
//             let selection_polynomial =
//                 get_selection_polynomial::<E>(index, self.we.kzg().max_degree());
//             let evaluation = evaluate_polynomial::<E>(
//                 &selection_polynomial,
//                 &E::ScalarField::from(index as u64),
//             );

//             let enc_message = self.we.encrypt_single(
//                 commitment,
//                 E::ScalarField::from(index as u64),
//                 evaluation,
//                 &message,
//             )?;

//             encrypted_messages.push(enc_message);
//         }

//         Ok(encrypted_messages)
//     }
// }

// /// Generates a selection polynomial from a selection and a max degree.
// fn get_selection_polynomial<E: Pairing>(
//     selection: usize,
//     max_degree: usize,
// ) -> Vec<E::ScalarField> {
//     let mut selection_polynomial = vec![E::ScalarField::ZERO; max_degree];
//     selection_polynomial[selection] = E::ScalarField::ONE;
//     selection_polynomial
// }

// #[cfg(test)]
// mod laconic_ot_tests {
//     use super::*;
//     use ark_bls12_381::{
//         g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
//         g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
//         Bls12_381, Fr, G1Affine, G2Affine,
//     };
//     use ark_std::{test_rng, UniformRand};
//     use keaki::{kzg::KZG, we::WE};
//     use rand::Rng;

//     const MAX_DEGREE: usize = 4;

//     /// Setups the KZG instance.
//     fn setup_kzg() -> KZG<Bls12_381> {
//         let rng = &mut test_rng();
//         let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
//         let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);
//         let secret = Fr::rand(rng);

//         KZG::setup(g1_generator.into(), g2_generator.into(), MAX_DEGREE, secret)
//     }

//     #[test]
//     fn test_laconic_ot() {
//         let rng = &mut test_rng();
//         let kzg = setup_kzg();
//         let we: WE<Bls12_381> = WE::new(kzg);

//         // --------------------
//         // ----- Receiver -----
//         // --------------------

//         // Make a random selection
//         let selection: usize = rng.gen_range(0..MAX_DEGREE);

//         // Instantiate the Receiver
//         let receiver = OTReceiver::new(we.clone(), selection);

//         // Commit
//         let commitment = receiver.commit().unwrap();

//         // --------------------
//         // ------ Sender ------
//         // --------------------

//         // Generate 4 random values
//         const VALUE_LENGTH: usize = 32;
//         let mut values: Vec<&[u8]> = Vec::with_capacity(MAX_DEGREE);

//         for _ in 0..MAX_DEGREE {
//             let mut value: Vec<u8> = Vec::with_capacity(VALUE_LENGTH);

//             for _ in 0..VALUE_LENGTH {
//                 let val: u8 = rng.gen();

//                 value.push(val);
//             }

//             values.push(value.leak());
//         }

//         // Instantiate the Sender
//         let sender = OTSender::new(we.clone());

//         // Encrypt
//         let encrypted_messages = sender.encrypt(&values, commitment).unwrap();

//         // --------------------
//         // ----- Receiver -----
//         // --------------------

//         // Decrypt
//         let decrypted_messages = receiver.decrypt(encrypted_messages).unwrap();

//         let mut decrypted_values = Vec::new();
//         for message in decrypted_messages {
//             // Assert message length
//             assert_eq!(message.len(), SUCCESSFUL_DECRYPTION_PAD + VALUE_LENGTH);

//             if message.starts_with(SUCCESSFUL_DECRYPTION) {
//                 let value: Vec<u8> = message[SUCCESSFUL_DECRYPTION.len()..].to_vec();

//                 decrypted_values.push(value);
//             }
//         }

//         // Assert that the receiver can only decrypt the message corresponding to the selection
//         assert_eq!(decrypted_values.len(), 1);

//         // Assert that the decrypted value is the same as the value at the selection index from the sender
//         assert_eq!(decrypted_values[0], values[selection]);
//     }
// }
