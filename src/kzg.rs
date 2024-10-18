//! # KZG Polynomial Commitment Scheme
//!
//! This module contains the implementation of the KZG polynomial commitment scheme.

pub mod setup;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_std::{
    ops::{Div, Mul, Sub},
    vec::Vec,
};
use setup::{get_powers_from_file, SetupFileError};
use thiserror::Error;

/// KZG polynomial commitment scheme.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KZG<E: Pairing> {
    /// Powers of tau in G1 - [tau^i]_1
    g1_pow: Vec<E::G1>,
    /// Powers of tau in G2 - [tau^i]_2
    g2_pow: Vec<E::G2>,
}

impl<E: Pairing> KZG<E> {
    /// Initializes the KZG commitment scheme from a trusted setup file.
    pub fn new_from_file(file: &str) -> Result<Self, KZGError> {
        let (g1_pow, g2_pow) = get_powers_from_file::<E>(file)?;

        Ok(Self { g1_pow, g2_pow })
    }

    /// Initializes the KZG commitment scheme from a given secret.
    /// This is recommended for **testing purposes only**, since it requires the secret to be known.
    pub fn setup(secret: E::ScalarField, max_d: usize) -> Self {
        let mut g1_pow = Vec::with_capacity(max_d + 1);
        let mut g2_pow = Vec::with_capacity(max_d + 1);

        for i in 0..=max_d {
            g1_pow.push(g1_gen::<E>().mul(secret.pow([i as u64])));
            g2_pow.push(g2_gen::<E>().mul(secret.pow([i as u64])));
        }

        Self { g1_pow, g2_pow }
    }

    /// Commits to a polynomial.
    pub fn commit(&self, p: &DensePolynomial<E::ScalarField>) -> Result<E::G1, KZGError> {
        if p.len() > self.g1_pow.len() {
            return Err(KZGError::PolynomialTooLarge(p.len(), self.g1_pow.len()));
        }

        let mut commitment = E::G1::zero();

        // Scalar multiplication of the polynomial coefficients with the powers in G1
        // commitment = sum(p[i] * g1_powers[i])
        for (i, &coeff) in p.coeffs.iter().enumerate() {
            commitment += self.g1_pow[i] * coeff;
        }

        Ok(commitment)
    }

    /// Computes an opening (proof) for a polynomial at a point.
    pub fn open(
        &self,
        p: &DensePolynomial<E::ScalarField>,
        point: &E::ScalarField,
    ) -> Result<E::G1, KZGError> {
        let value = p.evaluate(point);

        // p(point)
        let p_value = DensePolynomial::from_coefficients_slice(&[value]);

        // p(x) - p(point)
        let numerator = p.sub(&p_value);

        // x - point
        let denominator = DensePolynomial::from_coefficients_slice(&[-*point, E::ScalarField::ONE]);

        let quotient = numerator.div(&denominator);

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
    ) -> Result<bool, KZGError> {
        // [beta]_1
        let value_in_g1 = g1_gen::<E>().mul(value);

        // [tau]_2
        let tau_in_g2 = self.tau_g2()?;

        // [1]_2
        let g2_gen = g2_gen::<E>();

        // [alpha]_2
        let point_in_g2 = g2_gen.mul(point);

        // e(commitment - [beta]_1, [1]_2) == e(proof, [tau]_2 - [alpha]_2)
        let v = E::pairing(commitment - value_in_g1, g2_gen)
            == E::pairing(proof, tau_in_g2 - point_in_g2);

        Ok(v)
    }

    /// Computes openings for a polynomial at multiple points.
    /// The openings poins are the n-th roots of unity.
    pub fn set_open(&self, p: &[E::ScalarField]) -> Result<Vec<E::G1>, KZGError> {
        // Create evaluation domains
        let d = p.len();
        let domain = Radix2EvaluationDomain::<<E as Pairing>::ScalarField>::new(d).unwrap();
        let domain_2d = Radix2EvaluationDomain::<<E as Pairing>::ScalarField>::new(2 * d).unwrap();

        // s = ([s[d−1]], [s[d−2]], ..., [s], [1], [0], [0], ..., [0])
        // Where there are d neutral elements at the end
        let mut s = Vec::with_capacity(2 * d);
        for i in (0..d).rev() {
            s.push(self.g1_pow()[i]);
        }
        for _ in 0..d {
            s.push(E::G1::zero());
        }

        // hat_s = DFT_2d(s)
        let hat_s = domain_2d.fft(&s);

        // a = (0, 0, ..., 0, f1, f2, ..., fd)
        // Where there are d neutral elements at the beginning
        let mut a = Vec::with_capacity(2 * d);
        for _ in 0..d {
            a.push(E::ScalarField::zero());
        }
        for &coeff in p {
            a.push(coeff);
        }

        // hat_a = DFT_2d(a)
        let hat_a = domain_2d.fft(&a);

        // hat_h = hat_a * hat_s
        let mut hat_h: Vec<E::G1> = Vec::with_capacity(2 * d);
        for i in 0..2 * d {
            hat_h.push(hat_s[i].mul(hat_a[i]));
        }

        // hat_h = iDFt_2d(u)
        let h_prime = domain_2d.ifft(&hat_h);

        // Take first d elements of h_prime as h
        let h = h_prime[0..p.len()].to_vec();

        // Evaluate h in each n-th root of unity
        let ct = domain.fft(&h);

        Ok(ct)
    }

    /// Returns the powers of tau in G1.
    pub fn g1_pow(&self) -> &[E::G1] {
        &self.g1_pow
    }

    /// Returns [tau]_2
    pub fn tau_g2(&self) -> Result<E::G2, KZGError> {
        self.g2_pow.get(1).copied().ok_or(KZGError::G2PowersEmpty)
    }
}

/// Returns the G1 generator in projective coordinates.
pub fn g1_gen<E: Pairing>() -> E::G1 {
    E::G1Affine::generator().into()
}

/// Returns the G2 generator in projective coordinates.
pub fn g2_gen<E: Pairing>() -> E::G2 {
    E::G2Affine::generator().into()
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum KZGError {
    #[error("G2 powers of tau are empty")]
    G2PowersEmpty,
    #[error("Can't commit to polynomial: polynomial has degree {0} but max degree is {1}")]
    PolynomialTooLarge(usize, usize),
    #[error("Setup file error: {0}")]
    SetupFileError(SetupFileError),
}

impl From<SetupFileError> for KZGError {
    fn from(err: SetupFileError) -> Self {
        KZGError::SetupFileError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Config as BLS12Config, Fr, G1Projective};
    use ark_ec::{bls12::Bls12Config, short_weierstrass::SWCurveConfig};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_kzg_setup() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 3;

        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);

        // G1
        assert_eq!(kzg.g1_pow.len(), max_degree + 1);
        for i in 0..=max_degree {
            assert_eq!(
                kzg.g1_pow[i],
                g1_gen::<Bls12_381>().mul(secret.pow([i as u64]))
            );
        }

        // G2
        assert_eq!(kzg.g2_pow.len(), max_degree + 1);
        for i in 0..=max_degree {
            assert_eq!(
                kzg.g2_pow[i],
                g2_gen::<Bls12_381>().mul(secret.pow([i as u64]))
            );
        }

        // [tau]_2
        assert_eq!(kzg.tau_g2().unwrap(), g2_gen::<Bls12_381>().mul(secret));
    }

    #[test]
    fn test_generators() {
        let expected_g1_gen = <BLS12Config as Bls12Config>::G1Config::GENERATOR;
        let expected_g2_gen = <BLS12Config as Bls12Config>::G2Config::GENERATOR;

        let g1_gen = g1_gen::<Bls12_381>();
        let g2_gen = g2_gen::<Bls12_381>();

        assert_eq!(g1_gen, expected_g1_gen);
        assert_eq!(g2_gen, expected_g2_gen);
    }

    #[test]
    fn test_kzg_commit() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 2;
        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);

        // 2 x^2 + 3 x + 1
        let p = DensePolynomial::from_coefficients_slice(&[Fr::from(1), Fr::from(3), Fr::from(2)]);
        let commitment = kzg.commit(&p).unwrap();

        let mut expected_commitment = G1Projective::zero();
        for (i, &coeff) in p.iter().enumerate() {
            expected_commitment += kzg.g1_pow[i] * coeff;
        }

        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn test_kzg_commit_polynomial_too_large() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 2;
        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(1),
            Fr::from(3),
            Fr::from(2),
            Fr::from(4),
        ]);

        let result = kzg.commit(&p);
        let expected_err = KZGError::PolynomialTooLarge(p.len(), max_degree + 1);

        assert_eq!(result, Err(expected_err));
    }

    #[test]
    fn test_kzg_open_polynomial_too_large() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 2;
        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::from(6),
        ]);

        let point = Fr::from(5);

        let value = p.evaluate(&point);
        let numerator = p.sub(&DensePolynomial::from_coefficients_slice(&[value]));
        let denominator = DensePolynomial::from_coefficients_slice(&[
            -point,
            <Bls12_381 as Pairing>::ScalarField::ONE,
        ]);
        let quotient = numerator.div(&denominator);

        let result = kzg.open(&p, &point);
        let expected_err = KZGError::PolynomialTooLarge(quotient.len(), max_degree + 1);

        assert_eq!(result, Err(expected_err));
    }

    #[test]
    fn test_kzg_open_and_verify() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 2;
        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);

        // 2 x^2 + 3 x + 1
        let p = DensePolynomial::from_coefficients_slice(&[Fr::from(1), Fr::from(3), Fr::from(2)]);

        let commitment = kzg.commit(&p).unwrap();
        let point = Fr::from(5);

        // p(5) = 66
        let expected_value = Fr::from(66);

        let proof = kzg.open(&p, &point).unwrap();

        let v = kzg
            .verify(commitment, point, expected_value, proof)
            .unwrap();

        assert!(v);
    }

    #[test]
    fn test_kzg_verify_wrong_alpha() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 4;
        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let commitment = kzg.commit(&p).unwrap();
        let point = Fr::from(11);

        // p(11) = 113562
        let expected_value = Fr::from(113562);

        let proof = kzg.open(&p, &point).unwrap();
        let v_valid_point = kzg
            .verify(commitment, point, expected_value, proof)
            .unwrap();
        assert_eq!(v_valid_point, true);

        let wrong_point = Fr::from(99);
        let v_wrong_point = kzg
            .verify(commitment, wrong_point, expected_value, proof)
            .unwrap();
        assert_eq!(v_wrong_point, false);
    }

    #[test]
    fn test_kzg_verify_wrong_beta() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 4;
        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let commitment = kzg.commit(&p).unwrap();

        let point = Fr::from(6);

        // p(6) = 10662
        let expected_value = Fr::from(10662);

        let proof = kzg.open(&p, &point).unwrap();
        let v_valid_point = kzg
            .verify(commitment, point, expected_value, proof)
            .unwrap();
        assert_eq!(v_valid_point, true);

        let wrong_value = Fr::from(10663);
        let v_wrong_value = kzg.verify(commitment, point, wrong_value, proof).unwrap();
        assert_eq!(v_wrong_value, false);
    }

    #[test]
    fn test_kzg_verify_wrong_proof() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 4;
        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let commitment = kzg.commit(&p).unwrap();

        let point = Fr::from(6);

        // p(6) = 10662
        let value = Fr::from(10662);

        let proof = kzg.open(&p, &point).unwrap();
        let v_valid_point = kzg.verify(commitment, point, value, proof).unwrap();
        assert_eq!(v_valid_point, true);

        // Create a proof for a different polynomial
        let fake_p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-26),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);
        let wrong_proof = kzg.open(&fake_p, &point).unwrap();
        let v_wrong_proof = kzg.verify(commitment, point, value, wrong_proof).unwrap();
        assert_eq!(v_wrong_proof, false);
    }

    #[test]
    fn test_kzg_verify_wrong_commitment() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 4;
        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let commitment = kzg.commit(&p).unwrap();

        let point = Fr::from(6);

        // p(6) = 10662
        let value = Fr::from(10662);

        let proof = kzg.open(&p, &point).unwrap();
        let v_valid_commitment = kzg.verify(commitment, point, value, proof).unwrap();
        assert_eq!(v_valid_commitment, true);

        // Create a random commitment
        let wrong_com = commitment.mul(Fr::from(2));
        let v_wrong_commitment = kzg.verify(wrong_com, point, value, proof).unwrap();
        assert_eq!(v_wrong_commitment, false);
    }

    #[test]
    fn test_kzg_set_open() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 20;
        let kzg = KZG::<Bls12_381>::setup(secret, max_degree);

        // Create commitment polynomial
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
        ]);

        // Calculate proofs
        let proofs = kzg.set_open(&p).unwrap();

        // Create evaluation domain
        let domain =
            Radix2EvaluationDomain::<<Bls12_381 as Pairing>::ScalarField>::new(p.len()).unwrap();
        let roots_of_unity = domain.elements();

        // Open the polynomial at the evaluation points
        let mut expected_proofs = Vec::new();
        for root in roots_of_unity {
            let proof = kzg.open(&p, &root).unwrap();
            expected_proofs.push(proof);
        }

        for i in 0..p.len() {
            assert_eq!(proofs[i], expected_proofs[i]);
        }
    }
}
