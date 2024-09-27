//! # Polynomial Operations
//!
//! This module contains functions to perform polynomial operations.

use ark_ec::pairing::Pairing;
use ark_ff::{Field, One, Zero};
use std::collections::HashSet;
use thiserror::Error;

/// Subtracts two polynomials.
pub fn subtract_polynomials<E: Pairing>(
    p: &[E::ScalarField],
    q: &[E::ScalarField],
) -> Vec<E::ScalarField> {
    let min_len = p.len().min(q.len());
    let mut res = Vec::with_capacity(p.len().max(q.len()));

    // Subtract the overlapping parts
    for i in 0..min_len {
        res.push(p[i] - q[i]);
    }

    // Handle remaining terms in the longer polynomial
    if p.len() > min_len {
        res.extend_from_slice(&p[min_len..]);
    } else {
        for &coeff in &q[min_len..] {
            res.push(-coeff);
        }
    }

    res
}

/// Multiplies two polynomials.
pub fn multiply_polynomials<E: Pairing>(
    p: &[E::ScalarField],
    q: &[E::ScalarField],
) -> Vec<E::ScalarField> {
    let mut result = vec![E::ScalarField::zero(); p.len() + q.len() - 1];

    for (i, &coeff_a) in p.iter().enumerate() {
        for (j, &coeff_b) in q.iter().enumerate() {
            result[i + j] += coeff_a * coeff_b;
        }
    }

    result
}

/// Divides two polynomials using long division.
/// Returns the quotient.
pub fn divide_polynomials<E: Pairing>(
    num: &[E::ScalarField],
    den: &[E::ScalarField],
) -> Result<Vec<E::ScalarField>, OperationError> {
    // Check for division by zero polynomial
    if den.is_empty() || den.iter().all(|&x| x.is_zero()) {
        return Err(OperationError::DivisionByZero);
    }

    if num.len() < den.len() {
        return Err(OperationError::DenominatorTooLarge);
    }

    let coeff_diff = num.len() - den.len();
    let mut quotient = vec![E::ScalarField::zero(); coeff_diff + 1];
    let mut remainder = num.to_vec();

    for i in (0..=coeff_diff).rev() {
        let lead_coeff_ratio =
            remainder[i + den.len() - 1] / den.last().ok_or(OperationError::InsufficientTerms)?;

        // Assign the quotient coefficient
        quotient[i] = lead_coeff_ratio;

        for (j, &den_coeff) in den.iter().enumerate() {
            // Subtract the product of the quotient coefficient and the denominator coefficient
            remainder[i + j] -= lead_coeff_ratio * den_coeff;
        }
    }

    while let Some(true) = remainder.last().map(|x| x.is_zero()) {
        remainder.pop();
    }

    Ok(quotient)
}

/// Evaluates a polynomial at a given point.
pub fn evaluate_polynomial<E: Pairing>(
    p: &[E::ScalarField],
    point: &E::ScalarField,
) -> E::ScalarField {
    let mut result = E::ScalarField::zero();
    let mut power = E::ScalarField::one();

    // Horner's polynomial evaluation
    for &coefficient in p.iter() {
        result += coefficient * power;
        power *= point;
    }

    result
}

/// Generates the zero polynomial.
/// Returns a polynomial that evaluates to zero at each of the given points.
pub fn zero_polynomial<E: Pairing>(points: &[E::ScalarField]) -> Vec<E::ScalarField> {
    let mut result = vec![E::ScalarField::ONE];

    for &point in points {
        // Multiply the polynomial by (x - point)
        result = multiply_polynomials::<E>(&result, &[-point, E::ScalarField::ONE]);
    }

    result
}

/// Performs Lagrange interpolation over a given set of points.
/// Receives two arrays, one with the points and the other with the evaluations.
/// Returns the coefficients of the resulting polynomial.
pub fn lagrange_interpolation<E: Pairing>(
    points: &[E::ScalarField],
    values: &[E::ScalarField],
) -> Result<Vec<E::ScalarField>, OperationError> {
    let points_n = points.len();
    let mut result = vec![E::ScalarField::zero(); points_n];
    let mut seen_points = HashSet::with_capacity(points_n);

    // Check for a mismatch between the number of points and values
    if points_n != values.len() {
        return Err(OperationError::PointsValuesMismatch);
    }

    // Check for repeated points
    for point in points {
        if !seen_points.insert(point) {
            return Err(OperationError::RepeatedPoints);
        }
    }

    for j in 0..points_n {
        // Initialize the basis polynomial
        let mut basis_poly = vec![E::ScalarField::ONE];

        for k in 0..points_n {
            // Continue if we are at the same point (denominator will be zero)
            if k == j {
                continue;
            }

            // Multiply the basis polynomial by (x - x_k) for all k != j
            basis_poly = multiply_polynomials::<E>(&basis_poly, &[-points[k], E::ScalarField::ONE]);

            // Divide each coefficient by (x_j - x_k)
            for coeff in &mut basis_poly {
                *coeff /= points[j] - points[k];
            }
        }

        // Multiply by y_j and add to the result
        for i in 0..points_n {
            result[i] += basis_poly[i] * values[j];
        }
    }

    Ok(result)
}

#[derive(Error, Debug)]
pub enum OperationError {
    #[error("Cannot divide by polynomial of higher degree.")]
    DenominatorTooLarge,
    #[error("Division by zero polynomial is not allowed.")]
    DivisionByZero,
    #[error("Lagrange interpolation received repeated points.")]
    RepeatedPoints,
    #[error("Different lengths for the points and values arrays.")]
    PointsValuesMismatch,
    #[error("Insufficient terms in the denominator polynomial.")]
    InsufficientTerms,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_subtract_polynomials_same_length() {
        // p(x) = 4 x^2 + 2 x + 3
        let p = vec![Fr::from(3), Fr::from(2), Fr::from(4)];
        // q(x) = 3 x^2 + 2 x + 1
        let q = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
        // r(x) = x^2 + 2
        let r = vec![Fr::from(2), Fr::from(0), Fr::from(1)];

        let result = subtract_polynomials::<Bls12_381>(&p, &q);
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_subtract_polynomials_different_lengths() {
        // p(x) = 4 x^3 + 2 x^2 + 3 x + 6
        let p = vec![Fr::from(6), Fr::from(3), Fr::from(2), Fr::from(4)];
        // q(x) = 3 x^2 + 2 x
        let q = vec![Fr::from(0), Fr::from(2), Fr::from(3)];
        // r(x) = 4 x^3 - x^2 + x + 6
        let r = vec![Fr::from(6), Fr::from(1), Fr::from(-1), Fr::from(4)];

        let result = subtract_polynomials::<Bls12_381>(&p, &q);
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_subtract_polynomials_negative() {
        // p(x) = x^2 + 2 x + 1
        let p = vec![Fr::from(1), Fr::from(2), Fr::from(1)];
        // q(x) = 3 x^2 + 4 x + 5
        let q = vec![Fr::from(5), Fr::from(4), Fr::from(3)];
        // r(x) = -2 x^2 - 2 x - 4
        let r = vec![Fr::from(-4), Fr::from(-2), Fr::from(-2)];

        let result = subtract_polynomials::<Bls12_381>(&p, &q);
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_multiply_polynomials_same_length() {
        // p(x) = x^2 + 2 x + 3
        let p = vec![Fr::from(3), Fr::from(2), Fr::from(1)];
        // q(x) = 4 x^2 + 5 x + 6
        let q = vec![Fr::from(6), Fr::from(5), Fr::from(4)];
        // r(x) = 4 x^4 + 13 x^3 + 28 x^2 + 27 x + 18
        let r = vec![
            Fr::from(18),
            Fr::from(27),
            Fr::from(28),
            Fr::from(13),
            Fr::from(4),
        ];

        let result = multiply_polynomials::<Bls12_381>(&p, &q);
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_multiply_polynomials_different_lengths() {
        // p(x) = x + 2
        let p = vec![Fr::from(2), Fr::from(1)];
        // q(x) = 3 x^2 + 4 x + 5
        let q = vec![Fr::from(5), Fr::from(4), Fr::from(3)];
        // r(x) = 3x^3 + 10x^2 + 13x + 10
        let r = vec![Fr::from(10), Fr::from(13), Fr::from(10), Fr::from(3)];

        let result = multiply_polynomials::<Bls12_381>(&p, &q);
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_multiply_polynomials_with_zero() {
        // p(x) = 6 x^2 + 11 x + 6
        let p = vec![Fr::from(6), Fr::from(11), Fr::from(6)];
        // q(x) = 0
        let q = vec![Fr::from(0)];
        // r(x) = 0
        let r = vec![Fr::from(0), Fr::from(0), Fr::from(0)];

        let result = multiply_polynomials::<Bls12_381>(&p, &q);
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_divide_polynomials_exact_division() {
        // num(x) = 2100 x^4 + 1210 x^3 - 5 x^2 - 25 x - 24
        let p = vec![
            Fr::from(-24),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(1210),
            Fr::from(2100),
        ];
        // den(x) = 5 x + 3
        let q = vec![Fr::from(3), Fr::from(5)];
        // r(x) = 420 x^3 - 10 x^2 + 5 x -8
        let r = vec![Fr::from(-8), Fr::from(5), Fr::from(-10), Fr::from(420)];

        let result = divide_polynomials::<Bls12_381>(&p, &q).unwrap();
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_divide_polynomials_with_remainder() {
        // num(x) = 2100 x^4 + 1210 x^3 - 5 x^2 - 25 x + 45
        let p = vec![
            Fr::from(45),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(1210),
            Fr::from(2100),
        ];
        // den(x) = 5 x + 3
        let q = vec![Fr::from(3), Fr::from(5)];
        // r(x) = 420 x^3 - 10 x^2 + 5 x -8
        let r = vec![Fr::from(-8), Fr::from(5), Fr::from(-10), Fr::from(420)];

        let result = divide_polynomials::<Bls12_381>(&p, &q).unwrap();
        for i in 0..r.len() {
            // println!("{:?} {:?}", result[i], r[i]); // TODO: Add logging
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_divide_polynomials_by_zero_polynomial() {
        // num(x) = x + 2
        let p = vec![Fr::from(2), Fr::from(1)];
        // den(x) = 0
        let q = vec![Fr::from(0)];

        let result = divide_polynomials::<Bls12_381>(&p, &q);
        assert!(matches!(result, Err(OperationError::DivisionByZero)));
    }

    #[test]
    fn test_divide_polynomials_num_degree_less_than_den() {
        // num(x) = x + 2
        let p = vec![Fr::from(2), Fr::from(1)];
        // den(x) = x^2 + 1
        let q = vec![Fr::from(1), Fr::from(0), Fr::from(1)];

        let result = divide_polynomials::<Bls12_381>(&p, &q);
        assert!(matches!(result, Err(OperationError::DenominatorTooLarge)));
    }

    #[test]
    fn test_evaluate_polynomial_at_zero() {
        // 2100 x^4 + 1210 x^3 - 5 x^2 - 25 x + 45
        let p = vec![
            Fr::from(45),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(1210),
            Fr::from(2100),
        ];

        // Evaluating at x = 0, we should get the constant term
        let result = evaluate_polynomial::<Bls12_381>(&p, &Fr::zero());
        assert!(Fr::eq(&result, &Fr::from(45)));
    }

    #[test]
    fn test_evaluate_polynomial_at_one() {
        // 2100 x^4 + 1210 x^3 - 5 x^2 - 25 x + 45
        let p = vec![
            Fr::from(45),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(1210),
            Fr::from(2100),
        ];

        // Evaluating at x = 1, we should get the sum of all coefficients
        let result = evaluate_polynomial::<Bls12_381>(&p, &Fr::one());
        assert!(Fr::eq(&result, &Fr::from(3325)));
    }

    #[test]
    fn test_evaluate_polynomial_at_specific_value() {
        // 2100 x^4 + 1210 x^3 - 5 x^2 - 25 x + 45
        let p = vec![
            Fr::from(45),
            Fr::from(-25),
            Fr::from(-5),
            Fr::from(1210),
            Fr::from(2100),
        ];

        // Evaluating at x = 22
        let result = evaluate_polynomial::<Bls12_381>(&p, &Fr::from(22));
        assert!(Fr::eq(&result, &Fr::from(504818755)));
    }

    #[test]
    fn test_zero_polynomial_simple() {
        // (x - 2)(x - 3)(x - 5)
        let points = vec![Fr::from(2), Fr::from(3), Fr::from(5)];
        //  x^3 - 10 x^2 + 31 x - 30
        let r = vec![Fr::from(-30), Fr::from(31), Fr::from(-10), Fr::from(1)];

        let result = zero_polynomial::<Bls12_381>(&points);
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_zero_polynomial() {
        // (x + 7)(x - 22)(x + 32)(x - 4)(x + 89)
        let points = vec![
            Fr::from(-7),
            Fr::from(22),
            Fr::from(-32),
            Fr::from(4),
            Fr::from(-89),
        ];

        // x^5 + 102 x^4 + 455 x^3 - 64870 x^2 - 193176 x + 1754368
        let r = vec![
            Fr::from(1754368),
            Fr::from(-193176),
            Fr::from(-64870),
            Fr::from(455),
            Fr::from(102),
            Fr::from(1),
        ];

        let result = zero_polynomial::<Bls12_381>(&points);
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_zero_polynomial_duplicate_points() {
        // (x - 3)^2 * (x - 5)
        let points = vec![Fr::from(3), Fr::from(3), Fr::from(5)];
        // x^3 - 11 x^2 + 39 x - 45
        let r = vec![Fr::from(-45), Fr::from(39), Fr::from(-11), Fr::from(1)];

        let result = zero_polynomial::<Bls12_381>(&points);
        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_lagrange_interpolation() {
        // {{10, 100}, {15, 200}, {20, 500}}
        // p(10) = 100
        // p(15) = 200
        // p(20) = 500
        let points = vec![Fr::from(10), Fr::from(15), Fr::from(20)];
        let values = vec![Fr::from(100), Fr::from(200), Fr::from(500)];

        // r(x) = 4 x^2 - 80 x + 500
        let r = vec![Fr::from(500), Fr::from(-80), Fr::from(4)];

        let result = lagrange_interpolation::<Bls12_381>(&points, &values).unwrap();

        for i in 0..r.len() {
            assert!(Fr::eq(&result[i], &r[i]));
        }
    }

    #[test]
    fn test_lagrange_interpolation_identical_points_error() {
        let points = vec![Fr::from(10), Fr::from(10)];
        let values = vec![Fr::from(100), Fr::from(200)];

        let result = lagrange_interpolation::<Bls12_381>(&points, &values);
        assert!(matches!(result, Err(OperationError::RepeatedPoints)));
    }

    #[test]
    fn test_lagrange_interpolation_mismatched_error() {
        let points = vec![Fr::from(10), Fr::from(15)];
        let values = vec![Fr::from(100), Fr::from(200), Fr::from(500)];

        let result = lagrange_interpolation::<Bls12_381>(&points, &values);
        assert!(matches!(result, Err(OperationError::PointsValuesMismatch)));
    }
}
