//! # Witness Encryption Module
//!
//! This module contains the implementation of an Extractable Witness Encryption from Extractable Witness KEMs.

use crate::kem::KEM;
use ark_ec::pairing::Pairing;

/// Witness Encryption struct.
pub struct WE<E: Pairing> {
    kem: KEM<E>,
}

impl<E: Pairing> WE<E> {
    /// Create a new WE instance.
    pub fn new(kem: KEM<E>) -> Self {
        Self { kem }
    }

    /// Encrypts a message with a statement.
    /// Returns two ciphertexts.
    /// - ct_1: used to generate the decryption key.
    /// - ct_2: encrypted message.
    pub fn encrypt(&self, statement: &[E::ScalarField], message: &[u8]) -> (&[u8], &[u8]) {
        // Commit
        let com = self.kem.kzg().commit(statement).unwrap();

        // (ct_1, k) <- Encap(x)
        let x = self.kem.encapsulate_set(com, &[], &[]);

        // ct_2 <- Enc(k, m)
        // return (ct_1, ct_2)
        todo!()
    }

    /// Decrypts a ciphertext with a witness.
    /// Returns a message or an error if the decryption fails.
    pub fn decrypt(&self, witness: &[u8], ciphertext: (&[u8], &[u8])) -> Result<&[u8], ()> {
        // k = Decap(w, ct_1)
        // m = Dec(k, ct_2)
        // return m
        todo!()
    }
}
