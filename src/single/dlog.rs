use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_core::CryptoRngCore;

use crate::single::group::{GroupHasher, Hash};

// Note: one choice you could make for these structs is to have them take
// references to their data, instead of copying them. However, operations like
// scalar multiplication take a move instead of a reference, at least in arkworks,
// so you don't avoid a move by doing that.

#[derive(Clone, Copy, Debug)]
pub struct Statement<E: Pairing> {
    pub result: E::G1,
    pub base: E::G1,
}

#[derive(Clone, Copy, Debug)]
pub struct Witness<E: Pairing> {
    pub dlog: E::ScalarField,
}

/// A Proof of knowledge of the discrete logarithm of some element relative to another.
#[derive(Clone, Copy, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    big_k: E::G1,
    s: E::ScalarField,
}

impl<E: Pairing> Proof<E> {
    /// Hash this proof
    pub fn hash(&self) -> Hash {
        let mut hasher = GroupHasher::<E>::new(b"PC$:proof");
        hasher.eat_g1(&self.big_k);
        hasher.eat_f(&self.s);
        hasher.finalize_bytes()
    }
}

// This method is pulled out to be used in both proving and verifying.

/// Generate the challenge, given the context, statement, and nonce commitment.
fn challenge<E: Pairing>(ctx: &[u8], statement: &Statement<E>, big_k: &E::G1) -> E::ScalarField {
    let mut hasher = GroupHasher::<E>::new(b"PC$:proof_chal");
    hasher.eat_bytes(ctx);
    hasher.eat_g1(&statement.result);
    hasher.eat_g1(&statement.base);
    hasher.eat_g1(big_k);
    hasher.finalize()
}

/// Create a proof that one knows a discrete logarithm relative to a given base element.
///
/// This requires the statement, describing the base element, and the result of scalar
/// multiplication, along with a witness, holding the scalar used for this multiplication.
///
/// We also take in a context string; the proof will only verify with a matching string.
/// This allows binding a proof to a given context.
pub fn prove<E: Pairing, R: CryptoRngCore>(
    rng: &mut R,
    ctx: &[u8],
    statement: Statement<E>,
    witness: Witness<E>,
) -> Proof<E> {
    let k = E::ScalarField::rand(rng);
    let big_k = statement.base * k;

    let e = challenge(ctx, &statement, &big_k);

    let s = k + e * witness.dlog;

    Proof { big_k, s }
}

/// Verify a proof that one knows a discrete logarithm relative to a given base element.
///
/// This requires the statement, describing the base element, and the result of scalar
/// multiplication, and the proof to verify, in lieu of a witness.
///
/// We also take in a context string; the proof will only verify with a string matching
/// the one used to create the proof.
#[must_use]
pub fn verify<E: Pairing>(ctx: &[u8], statement: Statement<E>, proof: &Proof<E>) -> bool {
    let e = challenge(ctx, &statement, &proof.big_k);
    statement.base * proof.s == proof.big_k + statement.result * e
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_bn254::Bn254;
    use ark_ec::Group;
    use rand_core::OsRng;

    const TEST_CTX: &[u8] = b"Test Context";
    const NOT_TEST_CTX: &[u8] = b"Not Test Context";

    fn make_proof<E: Pairing>() -> (Statement<E>, Witness<E>, Proof<E>) {
        let dlog = E::ScalarField::rand(&mut OsRng);
        let base = E::G1::generator();
        let result = base * dlog;

        let statement = Statement { result, base };
        let witness = Witness { dlog };
        let proof = prove(&mut OsRng, TEST_CTX, statement, witness);

        (statement, witness, proof)
    }

    #[test]
    fn test_proof_happy_path() {
        let (statement, _, proof) = make_proof::<Bn254>();
        assert!(verify(TEST_CTX, statement, &proof));
    }

    #[test]
    fn test_different_big_k_makes_proof_fail() {
        let (statement, _, mut proof) = make_proof::<Bn254>();
        proof.big_k = <Bn254 as Pairing>::G1::generator();
        assert!(!verify(TEST_CTX, statement, &proof));
    }

    #[test]
    fn test_different_s_makes_proof_fail() {
        let (statement, _, mut proof) = make_proof::<Bn254>();
        proof.s = <Bn254 as Pairing>::ScalarField::rand(&mut OsRng);
        assert!(!verify(TEST_CTX, statement, &proof));
    }

    #[test]
    fn test_different_ctx_makes_proof_fail() {
        let (statement, _, proof) = make_proof::<Bn254>();
        assert!(!verify(NOT_TEST_CTX, statement, &proof));
    }

    #[test]
    fn test_bad_statement_makes_proof_fail() {
        let (mut statement, _, proof) = make_proof::<Bn254>();
        statement.result = statement.base;
        assert!(!verify(NOT_TEST_CTX, statement, &proof));
    }
}
