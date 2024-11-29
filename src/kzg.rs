//! # KZG Polynomial Commitment Scheme
//!
//! This module contains the implementation of the KZG polynomial commitment scheme.

pub mod ptau;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_std::{
    ops::{Div, Mul, Sub},
    vec::Vec,
};
use ptau::{get_powers_from_file, SetupFileError};
use thiserror::Error;

/// KZG Setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KZGSetup<E: Pairing> {
    /// Powers of tau in G1 - [tau^i]_1
    g1_pow: Vec<E::G1>,
    /// Powers of tau in G1 - Affine representation
    g1_aff: Vec<E::G1Affine>,
    /// [tau]_2
    tau_g2: E::G2,
}

impl<E: Pairing> KZGSetup<E> {
    /// Setup from `ptau` file.
    pub fn new_from_file(file: &str) -> Result<Self, SetupFileError> {
        let (g1_aff, g2_aff) = get_powers_from_file::<E>(file)?;
        let tau_g2 = g2_aff
            .get(1)
            .copied()
            .ok_or(SetupFileError::EmptySection(3))?
            .into();

        // Convert g1_aff to g1_pow
        let mut g1_pow: Vec<<E as Pairing>::G1> = Vec::with_capacity(g1_aff.len());
        for &element in g1_aff.iter() {
            g1_pow.push(element.into());
        }

        Ok(Self {
            g1_pow,
            g1_aff,
            tau_g2,
        })
    }

    /// Setup from secret. Don't use this.
    pub fn setup(secret: E::ScalarField, max_d: usize) -> Self {
        let mut g1_pow: Vec<<E as Pairing>::G1> = Vec::with_capacity(max_d);
        let tau_g2 = E::G2Affine::generator().mul(secret);

        for i in 0..max_d {
            g1_pow.push(E::G1Affine::generator().mul(secret.pow([i as u64])));
        }

        let g1_aff = E::G1::normalize_batch(&g1_pow);

        Self {
            g1_pow,
            g1_aff,
            tau_g2,
        }
    }

    /// Returns the powers of tau in G1.
    pub fn g1_pow(&self) -> &[E::G1] {
        &self.g1_pow
    }

    /// Returns the powers of tau in G1 - Affine representation.
    pub fn g1_aff(&self) -> &[E::G1Affine] {
        &self.g1_aff
    }

    /// Returns [tau]_2
    pub fn tau_g2(&self) -> &E::G2 {
        &self.tau_g2
    }
}

/// Commits to a polynomial.
pub fn commit<E: Pairing>(
    setup: &KZGSetup<E>,
    p: &DensePolynomial<E::ScalarField>,
) -> Result<E::G1, KZGError> {
    if p.len() > setup.g1_pow.len() {
        return Err(KZGError::PolynomialTooLarge(p.len(), setup.g1_pow.len()));
    }

    // commitment = sum(p[i] * g1_powers[i])
    let com = <E::G1 as VariableBaseMSM>::msm_unchecked(&setup.g1_aff, p);

    Ok(com)
}

/// Computes an opening (proof) for a polynomial at a point.
pub fn open<E: Pairing>(
    setup: &KZGSetup<E>,
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
    commit(setup, &quotient)
}

/// Verifies an opening proof for a polynomial commitment at a point.
pub fn verify<E: Pairing>(
    setup: &KZGSetup<E>,
    commitment: E::G1,
    point: E::ScalarField,
    value: E::ScalarField,
    proof: E::G1,
) -> Result<bool, KZGError> {
    // [beta]_1
    let value_in_g1 = E::G1Affine::generator().mul(value);

    // [tau]_2
    let tau_in_g2 = setup.tau_g2;

    // [1]_2
    let g2_gen = E::G2Affine::generator();

    // [alpha]_2
    let point_in_g2 = g2_gen.mul(point);

    // e(commitment - [beta]_1, [1]_2) == e(proof, [tau]_2 - [alpha]_2)
    let v =
        E::pairing(commitment - value_in_g1, g2_gen) == E::pairing(proof, tau_in_g2 - point_in_g2);

    Ok(v)
}

/// Computes n openings using the FK23 algorithm.
/// The amount of openings will depend on the length of the polynomial.
/// The openings points are the roots of unity of the domain.
/// - `domain_d` is an evaluation domain of size d.
pub fn open_fk<E: Pairing>(
    setup: &KZGSetup<E>,
    p: &[E::ScalarField],
    domain_d: &Radix2EvaluationDomain<E::ScalarField>,
) -> Result<Vec<E::G1>, KZGError> {
    let d = p.len();
    let domain_2d = Radix2EvaluationDomain::<<E as Pairing>::ScalarField>::new(2 * d).unwrap();

    // s = ([s[d−1]], [s[d−2]], ..., [s], [1], [0], [0], ..., [0])
    // d neutral elements at the end
    let mut s: Vec<<E as Pairing>::G1> = vec![E::G1::zero(); 2 * d];
    s[..d].copy_from_slice(
        &setup.g1_pow()[..d]
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>(),
    );

    // a = (0, 0, ..., 0, f1, f2, ..., fd)
    // d neutral elements at the beginning
    let mut a: Vec<<E as Pairing>::ScalarField> = vec![E::ScalarField::zero(); 2 * d];
    a[d..].copy_from_slice(p);

    // hat_s = DFT_2d(s)
    let hat_s = domain_2d.fft(&s);

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
    let h = h_prime[0..d].to_vec();

    // Evaluate h in each n-th root of unity
    let ct = domain_d.fft(&h);

    Ok(ct)
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum KZGError {
    #[error("Can't commit to polynomial: polynomial has degree {0} but max degree is {1}")]
    PolynomialTooLarge(usize, usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Projective};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_kzg_setup() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 4;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);

        // G1
        assert_eq!(kzg_setup.g1_pow.len(), max_degree);
        for i in 0..max_degree {
            assert_eq!(
                kzg_setup.g1_pow[i],
                <Bls12_381 as Pairing>::G1Affine::generator().mul(secret.pow([i as u64]))
            );
        }

        // [tau]_2
        assert_eq!(
            kzg_setup.tau_g2,
            <Bls12_381 as Pairing>::G2Affine::generator().mul(secret)
        );
    }

    #[test]
    fn test_kzg_commit() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 4;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);

        // 2 x^2 + 3 x + 1
        let p = DensePolynomial::from_coefficients_slice(&[Fr::from(1), Fr::from(3), Fr::from(2)]);
        let commitment = commit(&kzg_setup, &p).unwrap();

        let mut expected_commitment = G1Projective::zero();
        for (i, &coeff) in p.iter().enumerate() {
            expected_commitment += kzg_setup.g1_pow[i] * coeff;
        }

        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn test_kzg_commit_polynomial_too_large() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 2;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(1),
            Fr::from(3),
            Fr::from(2),
            Fr::from(4),
        ]);

        let result = commit(&kzg_setup, &p);
        let expected_err = KZGError::PolynomialTooLarge(p.len(), max_degree);

        assert_eq!(result, Err(expected_err));
    }

    #[test]
    fn test_kzg_open_polynomial_too_large() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 2;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);
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

        let result = open(&kzg_setup, &p, &point);
        let expected_err = KZGError::PolynomialTooLarge(quotient.len(), max_degree);

        assert_eq!(result, Err(expected_err));
    }

    #[test]
    fn test_kzg_open_and_verify() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 4;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);

        // 2 x^2 + 3 x + 1
        let p = DensePolynomial::from_coefficients_slice(&[Fr::from(1), Fr::from(3), Fr::from(2)]);

        let commitment = commit(&kzg_setup, &p).unwrap();
        let point = Fr::from(5);

        // p(5) = 66
        let expected_value = Fr::from(66);

        let proof = open(&kzg_setup, &p, &point).unwrap();

        let v = verify(&kzg_setup, commitment, point, expected_value, proof).unwrap();

        assert!(v);
    }

    #[test]
    fn test_kzg_verify_wrong_alpha() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 8;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let commitment = commit(&kzg_setup, &p).unwrap();
        let point = Fr::from(11);

        // p(11) = 113562
        let expected_value = Fr::from(113562);

        let proof = open(&kzg_setup, &p, &point).unwrap();
        let v_valid_point = verify(&kzg_setup, commitment, point, expected_value, proof).unwrap();
        assert_eq!(v_valid_point, true);

        let wrong_point = Fr::from(99);
        let v_wrong_point =
            verify(&kzg_setup, commitment, wrong_point, expected_value, proof).unwrap();
        assert_eq!(v_wrong_point, false);
    }

    #[test]
    fn test_kzg_verify_wrong_beta() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 8;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let commitment = commit(&kzg_setup, &p).unwrap();

        let point = Fr::from(6);

        // p(6) = 10662
        let expected_value = Fr::from(10662);

        let proof = open(&kzg_setup, &p, &point).unwrap();
        let v_valid_point = verify(&kzg_setup, commitment, point, expected_value, proof).unwrap();
        assert_eq!(v_valid_point, true);

        let wrong_value = Fr::from(10663);
        let v_wrong_value = verify(&kzg_setup, commitment, point, wrong_value, proof).unwrap();
        assert_eq!(v_wrong_value, false);
    }

    #[test]
    fn test_kzg_verify_wrong_proof() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 8;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let commitment = commit(&kzg_setup, &p).unwrap();

        let point = Fr::from(6);

        // p(6) = 10662
        let value = Fr::from(10662);

        let proof = open(&kzg_setup, &p, &point).unwrap();
        let v_valid_point = verify(&kzg_setup, commitment, point, value, proof).unwrap();
        assert_eq!(v_valid_point, true);

        // Create a proof for a different polynomial
        let fake_p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-26),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);
        let wrong_proof = open(&kzg_setup, &fake_p, &point).unwrap();
        let v_wrong_proof = verify(&kzg_setup, commitment, point, value, wrong_proof).unwrap();
        assert_eq!(v_wrong_proof, false);
    }

    #[test]
    fn test_kzg_verify_wrong_commitment() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 8;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);

        // p(x) = 7 x^4 + 9 x^3 - 5 x^2 - 25 x - 24
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(9),
            Fr::from(7),
        ]);

        let commitment = commit(&kzg_setup, &p).unwrap();

        let point = Fr::from(6);

        // p(6) = 10662
        let value = Fr::from(10662);

        let proof = open(&kzg_setup, &p, &point).unwrap();
        let v_valid_commitment = verify(&kzg_setup, commitment, point, value, proof).unwrap();
        assert_eq!(v_valid_commitment, true);

        // Create a random commitment
        let wrong_com = commitment.mul(Fr::from(2));
        let v_wrong_commitment = verify(&kzg_setup, wrong_com, point, value, proof).unwrap();
        assert_eq!(v_wrong_commitment, false);
    }

    #[test]
    fn test_kzg_open_fk() {
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);
        let max_degree = 16;
        let kzg_setup = KZGSetup::<Bls12_381>::setup(secret, max_degree);

        // Create commitment polynomial
        let p = DensePolynomial::from_coefficients_slice(&[
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
        ]);

        // Calculate proofs
        let domain =
            Radix2EvaluationDomain::<<Bls12_381 as Pairing>::ScalarField>::new(p.len()).unwrap();
        let proofs = open_fk(&kzg_setup, &p, &domain).unwrap();

        // Create evaluation domain
        let domain =
            Radix2EvaluationDomain::<<Bls12_381 as Pairing>::ScalarField>::new(p.len()).unwrap();
        let roots_of_unity = domain.elements();

        // Open the polynomial at the evaluation points
        let mut expected_proofs = Vec::new();
        for root in roots_of_unity {
            let proof = open(&kzg_setup, &p, &root).unwrap();
            expected_proofs.push(proof);
        }

        for i in 0..p.len() {
            assert_eq!(proofs[i], expected_proofs[i]);
        }
    }
}
