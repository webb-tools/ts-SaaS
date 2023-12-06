use ark_ec::{
    pairing::{Pairing, PairingOutput},
    scalar_mul::{variable_base::VariableBaseMSM, ScalarMul},
};
use ark_ff::PrimeField;
use ark_std::vec::Vec;

#[cfg(any(feature = "std", feature = "parallel"))]
use rand_core::CryptoRngCore;

// # Batched Pairing Checks

/// Sample a random field that's "small" but still big enough for pairing checks.
#[cfg(any(feature = "std", feature = "parallel"))]
pub fn rand_small_f<E: Pairing, R: CryptoRngCore>(rng: &mut R) -> E::ScalarField {
    // 128 bits of security
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    E::ScalarField::from_le_bytes_mod_order(&bytes)
}

/// The pairing operation between the two groups.
pub fn pairing<E: Pairing>(
    a: impl Into<E::G1Prepared>,
    b: impl Into<E::G2Prepared>,
) -> PairingOutput<E> {
    E::pairing(a, b)
}

// This is just a gimmick to support our macro shenanigans
pub fn swapped_pairing<E: Pairing>(
    a: impl Into<E::G2Prepared>,
    b: impl Into<E::G1Prepared>,
) -> PairingOutput<E> {
    pairing(b, a)
}

/// A tool for efficiently making many pairing checks.
///
/// This version is for pairing checks where the varying parts
/// of each side of the pairing equality are in $gl and $gr, respectively.
pub struct BatchedPairingChecker11<E: Pairing> {
    // Invariant: both vecs have the same length.
    vary_l: Vec<E::G1>,
    base_l: E::G2Prepared,
    vary_r: Vec<E::G1>,
    base_r: E::G2Prepared,
}

impl<E: Pairing> BatchedPairingChecker11<E> {
    pub fn new(base_l: impl Into<E::G2Prepared>, base_r: impl Into<E::G2Prepared>) -> Self {
        Self {
            vary_l: Vec::new(),
            base_l: base_l.into(),
            vary_r: Vec::new(),
            base_r: base_r.into(),
        }
    }

    pub fn add(&mut self, l: E::G1, r: E::G1) {
        self.vary_l.push(l);
        self.vary_r.push(r);
    }

    #[must_use]
    pub fn check<R: CryptoRngCore>(self, rng: &mut R) -> bool {
        let n = self.vary_l.len();
        let scalars = (0..n)
            .map(|_| rand_small_f::<E, R>(rng))
            .collect::<Vec<E::ScalarField>>();

        let ready_to_msm_l = <E::G1 as ScalarMul>::batch_convert_to_mul_base(&self.vary_l);
        let l = <E::G1 as VariableBaseMSM>::msm_unchecked(&ready_to_msm_l, &scalars);
        let ready_to_msm_r = <E::G1 as ScalarMul>::batch_convert_to_mul_base(&self.vary_r);
        let r = <E::G1 as VariableBaseMSM>::msm_unchecked(&ready_to_msm_r, &scalars);

        pairing::<E>(l, self.base_l) == swapped_pairing::<E>(self.base_r, r)
    }
}

pub struct BatchedPairingChecker12<E: Pairing> {
    // Invariant: both vecs have the same length.
    vary_l: Vec<E::G1>,
    base_l: E::G2Prepared,
    vary_r: Vec<E::G2>,
    base_r: E::G1Prepared,
}

impl<E: Pairing> BatchedPairingChecker12<E> {
    pub fn new(base_l: impl Into<E::G2Prepared>, base_r: impl Into<E::G1Prepared>) -> Self {
        Self {
            vary_l: Vec::new(),
            base_l: base_l.into(),
            vary_r: Vec::new(),
            base_r: base_r.into(),
        }
    }

    pub fn add(&mut self, l: E::G1, r: E::G2) {
        self.vary_l.push(l);
        self.vary_r.push(r);
    }

    #[must_use]
    #[cfg(any(feature = "std", feature = "parallel"))]
    pub fn check<R: CryptoRngCore>(self, rng: &mut R) -> bool {
        let n = self.vary_l.len();
        let scalars = (0..n)
            .map(|_| rand_small_f::<E, R>(rng))
            .collect::<Vec<E::ScalarField>>();

        let ready_to_msm_l = <E::G1 as ScalarMul>::batch_convert_to_mul_base(&self.vary_l);
        let l = <E::G1 as VariableBaseMSM>::msm_unchecked(&ready_to_msm_l, &scalars);
        let ready_to_msm_r = <E::G2 as ScalarMul>::batch_convert_to_mul_base(&self.vary_r);
        let r = <E::G2 as VariableBaseMSM>::msm_unchecked(&ready_to_msm_r, &scalars);

        pairing::<E>(l, self.base_l) == pairing::<E>(self.base_r, r)
    }
}
