//! KZG Module
//!
//! This module contains the implementation of the KZG polynomial commitment scheme.

use crate::operations::*;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, Zero};
use std::ops::Mul;

/// KZG polynomial commitment scheme.
pub struct KZG<E: Pairing> {
    /// G1 generator
    g1_gen: E::G1,
    /// G2 generator
    g2_gen: E::G2,
    /// Powers of tau in G1 - [tau^i]_1
    g1_pow: Vec<E::G1>,
    /// Powers of tau in G2 - [tau^i]_2
    g2_pow: Vec<E::G2>,
    /// Tau in G2 - [tau]_2
    tau_g2: E::G2,
    /// Maximum degree
    max_d: usize,
}

impl<E: Pairing> KZG<E> {
    /// Initializes the KZG commitment scheme.
    pub fn setup(g1_gen: E::G1, g2_gen: E::G2, max_d: usize, secret: E::ScalarField) -> Self {
        let tau_g2 = g2_gen.mul(secret);
        let mut g1_pow = Vec::with_capacity(max_d + 1);
        let mut g2_pow = Vec::with_capacity(max_d + 1);

        // Generate powers of tau for G1
        for i in 0..=max_d {
            g1_pow.push(g1_gen.mul(secret.pow([i as u64])));
            g2_pow.push(g2_gen.mul(secret.pow([i as u64])));
        }

        Self {
            g1_gen,
            g2_gen,
            g1_pow,
            g2_pow,
            tau_g2,
            max_d,
        }
    }

    /// Commits to a polynomial.
    pub fn commit(&self, p: &[E::ScalarField]) -> E::G1 {
        // Verify that the degree of the polynomial is less than or equal to the maximum degree
        assert!(
            p.len() <= self.max_d + 1,
            "Degree of polynomial exceeds the maximum degree"
        );

        let mut commitment = E::G1::zero();

        // Scalar multiplication of the polynomial coefficients with the powers in G1
        // commitment = sum(p[i] * g1_powers[i])
        for (i, &coeff) in p.iter().enumerate() {
            commitment += self.g1_pow[i] * coeff;
        }

        commitment
    }

    /// Computes an opening (proof) for a polynomial at a point.
    pub fn open(&self, p: &[E::ScalarField], point: E::ScalarField) -> E::G1 {
        let value = evaluate_polynomial::<E>(p, point);

        // p(x) - p(point)
        let numerator = subtract_polynomials::<E>(p, &[value]);

        // x - point
        let denominator = [-point, E::ScalarField::ONE];

        let quotient = divide_polynomials::<E>(&numerator, &denominator).unwrap();

        // Generate the proof by committing to the quotient polynomial
        self.commit(&quotient)
    }

    /// Verifies an opening proof for a polynomial commitment at a point.
    pub fn verify(
        &self,
        commitment: E::G1,
        point: E::ScalarField,
        value: E::ScalarField,
        proof: E::G1,
    ) -> bool {
        // [beta]_1
        let value_in_g1 = self.g1_gen.mul(value);

        // [alpha]_2
        let point_in_g2 = self.g2_gen.mul(point);

        // e(commitment - [beta]_1, [1]_2) == e(proof, [tau]_2 - [alpha]_2)
        E::pairing(commitment - value_in_g1, self.g2_gen)
            == E::pairing(proof, self.tau_g2 - point_in_g2)
    }

    /// Computes a batch opening for a polynomial at multiple points
    pub fn batch_open(&self, p: &[E::ScalarField], points: &[E::ScalarField]) -> E::G1 {
        // Compute the values of the polynomial at the points
        let mut values = vec![E::ScalarField::zero(); points.len()];
        for (i, &point) in points.iter().enumerate() {
            values[i] = evaluate_polynomial::<E>(p, point);
        }

        // Compute the LaGrange interpolation for the points - I(x)
        let lagrange_polynomial = lagrange_interpolation::<E>(points, &values).unwrap();

        // Subtract from the original polynomial
        // p(x) - I(x)
        let numerator = subtract_polynomials::<E>(p, &lagrange_polynomial);

        // Divide the numerator by the zero polynomial
        // (p(x) - I(x)) / Z(x)
        let quotient = divide_polynomials::<E>(&numerator, &zero_polynomial::<E>(points)).unwrap();

        // Generate the batch proof by committing to the quotient
        self.commit(&quotient)
    }

    /// Verifies a batch opening proof for multiple points
    pub fn batch_verify(
        &self,
        commitment: E::G1,
        points: &[E::ScalarField],
        values: &[E::ScalarField],
        proof: E::G1,
    ) -> bool {
        // Compute the LaGrange interpolation for the points - I(x)
        let lagrange_p = lagrange_interpolation::<E>(points, values).unwrap();

        // Compute the zero polynomial
        let zero_p = zero_polynomial::<E>(points);

        // Commit to the zero polynomial in G2
        let mut zero_p_com = E::G2::zero();
        for (i, &coeff) in zero_p.iter().enumerate() {
            zero_p_com += self.g2_pow[i] * coeff;
        }

        // e(commitment - [lagrange_p]_1, [1]_2) == e(proof, [zero_p]_2)
        E::pairing(commitment - self.commit(&lagrange_p), self.g2_gen)
            == E::pairing(proof, zero_p_com)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{
        g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
        g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
        Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
    };
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_kzg_setup() {
        let rng = &mut test_rng();
        let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
        let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);
        let max_degree = 10;
        let secret = Fr::rand(rng);

        let kzg =
            KZG::<Bls12_381>::setup(g1_generator.into(), g2_generator.into(), max_degree, secret);

        // Verify G1 powers
        assert_eq!(kzg.g1_pow.len(), max_degree + 1);
        for i in 0..=max_degree {
            assert_eq!(kzg.g1_pow[i], g1_generator.mul(secret.pow([i as u64])));
        }

        // Verify tau in G2
        assert_eq!(kzg.tau_g2, g2_generator.mul(secret));
    }

    #[test]
    fn test_kzg_setup_min_degree() {
        let rng = &mut test_rng();
        let g1_generator = G1Projective::rand(rng);
        let g2_generator = G2Projective::rand(rng);
        let max_degree = 0;
        let secret = Fr::rand(rng);

        let kzg = KZG::<Bls12_381>::setup(g1_generator, g2_generator, max_degree, secret);

        assert_eq!(kzg.g1_pow.len(), 1);
        assert_eq!(kzg.g1_pow[0], g1_generator.mul(secret.pow([0])));

        assert_eq!(kzg.tau_g2, g2_generator.mul(secret));
    }

    #[test]
    fn test_kzg_commit() {
        let rng = &mut test_rng();
        let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
        let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);
        let max_degree = 2;
        let secret = Fr::rand(rng);

        let kzg =
            KZG::<Bls12_381>::setup(g1_generator.into(), g2_generator.into(), max_degree, secret);

        // 2 x^2 + 3 x + 1
        let p = vec![Fr::from(1), Fr::from(3), Fr::from(2)];
        let commitment = kzg.commit(&p);

        let mut expected_commitment = G1Projective::zero();
        for (i, &coeff) in p.iter().enumerate() {
            expected_commitment += kzg.g1_pow[i] * coeff;
        }

        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn test_kzg_commit_zero_polynomial() {
        let rng = &mut test_rng();
        let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
        let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);
        let max_degree = 2;
        let secret = Fr::rand(rng);

        let kzg =
            KZG::<Bls12_381>::setup(g1_generator.into(), g2_generator.into(), max_degree, secret);

        let zero_polynomial = vec![Fr::zero(); max_degree + 1];
        let commitment = kzg.commit(&zero_polynomial);

        // Expected commitment should be the identity element in G1
        assert_eq!(commitment, G1Projective::zero());
    }

    #[test]
    fn test_kzg_open_and_verify() {
        let rng = &mut test_rng();
        let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
        let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);
        let max_degree = 2;
        let secret = Fr::rand(rng);

        let kzg =
            KZG::<Bls12_381>::setup(g1_generator.into(), g2_generator.into(), max_degree, secret);

        // 2 x^2 + 3 x + 1
        let p = vec![Fr::from(1), Fr::from(3), Fr::from(2)];

        // Generate commitment
        let commitment = kzg.commit(&p);

        // Point at which to open the commitment
        let point = Fr::from(5);

        // p(5) = 66
        let expected_value = Fr::from(66);

        // Compute the proof
        let proof = kzg.open(&p, point);

        assert!(kzg.verify(commitment, point, expected_value, proof));
    }

    #[test]
    fn test_kzg_batch_open_and_verify() {
        let rng = &mut test_rng();
        let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
        let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);
        let max_degree = 5;
        let secret = Fr::rand(rng);

        let kzg =
            KZG::<Bls12_381>::setup(g1_generator.into(), g2_generator.into(), max_degree, secret);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = vec![
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ];

        // Commit
        let commitment = kzg.commit(&p);

        // p(6) = 10662
        // p(11) = 113562
        // p(17) = 626970
        let points = vec![Fr::from(6), Fr::from(11), Fr::from(17)];
        let expected_values = vec![Fr::from(10662), Fr::from(113562), Fr::from(626970)];

        // Compute the batch proof
        let proof = kzg.batch_open(&p, &points);

        // Verify the batch proof
        assert!(kzg.batch_verify(commitment, &points, &expected_values, proof));
    }
}
