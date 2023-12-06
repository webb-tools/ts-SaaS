//! This module serves as a small abstraction layer over the group operations we need.
use ark_ec::pairing::Pairing;
use ark_ff::fields::PrimeField;
use ark_serialize::CanonicalSerialize;

/// The size of the hash we use.
pub(crate) const HASH_SIZE: usize = 32;

/// The hash output we use when we need bytes.
pub(crate) type Hash = [u8; 32];

/// A utility struct for hashing group elements and producing fields.
///
/// This avoids having to deal with some serialization and reduction code from arkworks.
///
/// All methods of this struct will handle separation between elements correctly.
/// This means that feeding in two elements is distinct from feeding in the "concatenation"
/// of this elements. One place where you still need manual effort on the user's end
/// is when you're hashing a variable number of elements.
#[derive(Clone)]
pub(crate) struct GroupHasher<E: Pairing> {
    state: StateWrapper,
    _marker: ark_std::marker::PhantomData<E>,
}

#[derive(Clone)]
pub struct StateWrapper {
    state: blake2b_simd::State,
}

impl StateWrapper {
    pub fn update(&mut self, x: &[u8]) {
        self.state.update(x);
    }

    pub fn finalize(self) -> blake2b_simd::Hash {
        self.state.finalize()
    }
}

impl ark_serialize::Write for StateWrapper {
    fn write(&mut self, buf: &[u8]) -> ark_std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> ark_std::io::Result<()> {
        Ok(())
    }
}

impl<E: Pairing> GroupHasher<E> {
    /// Create a new hasher with a personalization string.
    ///
    /// Because of BLAKE2's limitations, this has to be 16 bytes at most.
    /// This function will panic if that isn't the case.
    pub fn new(personalization: &'static [u8]) -> Self {
        let state = blake2b_simd::Params::new()
            .personal(personalization)
            .to_state();
        Self {
            state: StateWrapper { state },
            _marker: ark_std::marker::PhantomData,
        }
    }

    // Separate methods because the semantics of what this is trying to do are different,
    // even if eating a usize happens to do the right thing.
    fn write_len(&mut self, len: usize) {
        self.eat_usize(len);
    }

    /// Consume some bytes, adding it to the state of the hash.
    ///
    /// These bytes will be length prefixed, and so calling this function
    /// multiple times is not the same as calling it with the concatenation
    /// of those bytes.
    pub fn eat_bytes(&mut self, x: &[u8]) {
        self.write_len(x.len());
        self.state.update(x);
    }

    /// Eat anything that's canonically serializable (yummy!).
    ///
    /// This will handle padding between elements, using the declared length.
    ///
    /// We keep this internal, to make a simpler public API, since we only have
    /// a handful of types we actually need to use this for.
    fn eat_canonical<T: CanonicalSerialize>(&mut self, x: &T) {
        self.write_len(x.compressed_size());
        x.serialize_compressed(&mut self.state)
            .expect("failed to serialize element");
    }

    /// Consume a usize value, adding it into the state of this hash.
    ///
    /// This is useful for (i.e. intended for) encoding metadata.
    pub fn eat_usize(&mut self, x: usize) {
        // On basically any platform this should fit in a u64
        self.state.update(&(x as u64).to_le_bytes());
    }

    /// Consume a G1 group element, adding it into the state of this hash.
    pub fn eat_g1(&mut self, x: &E::G1) {
        self.eat_canonical(x);
    }

    /// Consume a G2 group element, adding it into the state of this hash.
    pub fn eat_g2(&mut self, x: &E::G2) {
        self.eat_canonical(x);
    }

    /// Consume a scalar, adding it into the state of this hash.
    pub fn eat_f(&mut self, x: &E::ScalarField) {
        self.eat_canonical(x);
    }

    /// Finalize this hash function, producing a scalar.
    pub fn finalize(self) -> E::ScalarField {
        E::ScalarField::from_le_bytes_mod_order(self.state.finalize().as_bytes())
    }

    /// Finalize this hash function, producing bytes.
    pub fn finalize_bytes(self) -> Hash {
        let mut out = [0u8; HASH_SIZE];
        out.copy_from_slice(&self.state.finalize().as_bytes()[..HASH_SIZE]);
        out
    }
}
