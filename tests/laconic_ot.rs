//! # Laconic OT
//!
//! This module contains the implementation of a Laconic Oblivious Transfer using we-kzg.

pub const MAX_DEGREE: usize = 4;
pub const SUCCESSFUL_DECRYPTION: &str = "Successful decryption";

#[cfg(test)]
mod laconic_ot_tests {
    use super::*;
    use ark_bls12_381::{
        g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
        g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
        Bls12_381, Fr, G1Affine, G2Affine,
    };
    use ark_ff::{BigInt, BigInteger};
    use ark_std::{test_rng, UniformRand};
    use keaki::{kzg::KZG, we::WE};
    use rand::Rng;

    #[test]
    fn test_laconic_ot() {
        let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
        let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);

        // Setup secret
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);

        let kzg: KZG<Bls12_381> =
            KZG::setup(g1_generator.into(), g2_generator.into(), MAX_DEGREE, secret);
        let we: WE<Bls12_381> = WE::new(kzg);

        // Receiver makes a random selection and commits to it
        let selection: usize = rng.gen_range(0..MAX_DEGREE);

        let mut selection_polynomial = vec![Fr::from(0); MAX_DEGREE];
        selection_polynomial[selection] = Fr::from(1);

        let commitment = we.kzg().commit(&selection_polynomial).unwrap();

        // Sender has a list of values
        let values = vec![Fr::rand(rng); MAX_DEGREE];

        let points = (0..MAX_DEGREE)
            .map(|i| Fr::from(i as u64))
            .collect::<Vec<Fr>>();

        // Sender encrypts the values using the receiver's commitment
        let mut encrypted_messages = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let mut message = Vec::from(SUCCESSFUL_DECRYPTION);
            let value = Vec::from(value.0.to_bytes_be());
            message.extend(value);

            let (key_ct, msg_ct) = we
                .encrypt_single(commitment, points[index], Fr::from(1), &message)
                .unwrap();
            encrypted_messages.push((key_ct, msg_ct));
        }

        // Receiver generates a proof for their selection
        let proof = we
            .kzg()
            .open(&selection_polynomial, &points[selection])
            .unwrap();

        // Receiver tries to decrypt the message
        for encrypted_message in encrypted_messages {
            let (key_ct, msg_ct) = encrypted_message;
            let decrypted_msg = we.decrypt_single(proof, key_ct, &msg_ct).unwrap().to_vec();

            if decrypted_msg.starts_with(SUCCESSFUL_DECRYPTION.as_bytes()) {
                // Get value
                let value: Vec<u8> = decrypted_msg[SUCCESSFUL_DECRYPTION.len()..].to_vec();

                // Convert to bits
                let mut value_bits: Vec<bool> = Vec::with_capacity(value.len() * 8);
                for byte in value {
                    for bit_index in (0..8).rev() {
                        value_bits.push((byte >> bit_index) & 1 == 1);
                    }
                }

                // Convert to Fr
                let value = Fr::from(BigInt::from_bits_be(&value_bits));

                // Check if the value is correct
                assert_eq!(values[selection], value);
            }
        }
    }
}
