use std::marker::PhantomData;

use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::HashFunction;
use rs_merkle::{Hasher, MerkleProof, MerkleTree as ExternalMerkleTree};

/// This represents a Merkle Tree with an arbitrary number of elements of type `T`. The [prove] function
/// can generate proofs that the leaf of a given index has a certain hash value.
///
/// New elements may be added continuously but once a verifier is generated with the [create_verifier]
/// function, the proofs are only valid for the state of the tree at that point.
///
/// To avoid second-preimage attacks, a 0x00 byte is prepended to the hash data for leaf nodes (see
/// [LeafHasher]), and 0x01 is prepended when computing internal node hashes (see [InternalNodeHasher]).
pub struct MerkleTree<const DIGEST_LENGTH: usize, H: HashFunction<DIGEST_LENGTH>, T: AsRef<[u8]>> {
    tree: ExternalMerkleTree<InternalNodeHasher<DIGEST_LENGTH, H>>,
    _type: PhantomData<T>,
}

impl<const DIGEST_LENGTH: usize, H: HashFunction<DIGEST_LENGTH>, T: AsRef<[u8]>>
    MerkleTree<DIGEST_LENGTH, H, T>
{
    pub fn new() -> Self {
        MerkleTree {
            tree: ExternalMerkleTree::new(),
            _type: PhantomData::default(),
        }
    }
}

/// This verifier can verify proofs generated by [MerkleTree::prove].
pub struct MerkleTreeVerifier<
    const DIGEST_LENGTH: usize,
    H: HashFunction<DIGEST_LENGTH>,
    T: AsRef<[u8]>,
> {
    root: [u8; DIGEST_LENGTH],
    number_of_leaves: usize,
    _hash_function: PhantomData<H>,
    _type: PhantomData<T>,
}

impl<const DIGEST_LENGTH: usize, H: HashFunction<DIGEST_LENGTH>, T: AsRef<[u8]>>
    MerkleTreeVerifier<DIGEST_LENGTH, H, T>
{
    /// Verify a [Proof] that an element with the given hash was at this index of this tree at the time
    /// this verifier was created.
    pub fn verify(
        &self,
        index: usize,
        leaf_hash: [u8; DIGEST_LENGTH],
        proof: &Proof<DIGEST_LENGTH, H, T>,
    ) -> bool {
        proof
            .proof
            .verify(self.root, &[index], &[leaf_hash], self.number_of_leaves)
    }

    /// Verify a [Proof] that an element was at this index of this tree at the time this verifier was
    /// created.
    pub fn verify_with_element(
        &self,
        index: usize,
        element: &T,
        proof: &Proof<DIGEST_LENGTH, H, T>,
    ) -> bool {
        self.verify(
            index,
            LeafHasher::<DIGEST_LENGTH, H>::hash(element.as_ref()),
            proof,
        )
    }
}

impl<const DIGEST_LENGTH: usize, H: HashFunction<DIGEST_LENGTH>, T: AsRef<[u8]>>
    MerkleTree<DIGEST_LENGTH, H, T>
{
    /// Insert element in this tree and return the index of the newly inserted element.
    pub fn insert(&mut self, element: &T) -> usize {
        let hash = LeafHasher::<DIGEST_LENGTH, H>::hash(element.as_ref());
        self.tree.insert(hash).commit();
        self.tree.leaves_len() - 1
    }

    /// Insert element in this tree and return the index of the last element.
    pub fn insert_all(&mut self, elements: &[T]) -> usize {
        let mut hashes = elements
            .into_iter()
            .map(|element| LeafHasher::<DIGEST_LENGTH, H>::hash(element.as_ref()))
            .collect();
        self.tree.append(&mut hashes).commit();
        self.tree.leaves_len() - 1
    }

    /// Create a proof for the element at the given index.
    pub fn prove(&self, index: usize) -> Proof<DIGEST_LENGTH, H, T> {
        Proof {
            proof: self.tree.proof(&[index]),
            _type: PhantomData::default(),
        }
    }

    /// Create a [MerkleTreeVerifier] for the current state of this tree.
    pub fn create_verifier(
        &self,
    ) -> Result<MerkleTreeVerifier<DIGEST_LENGTH, H, T>, FastCryptoError> {
        Ok(MerkleTreeVerifier {
            root: self
                .tree
                .root()
                .ok_or_else(|| FastCryptoError::GeneralError("Tree is empty".to_string()))?,
            number_of_leaves: self.tree.leaves_len(),
            _hash_function: PhantomData::default(),
            _type: PhantomData::default(),
        })
    }

    /// Return the number of leaves in this tree.
    pub fn number_of_leaves(&self) -> usize {
        self.tree.leaves_len()
    }

    /// Returns the root of this tree.
    pub fn root(&self) -> Result<[u8; DIGEST_LENGTH], FastCryptoError> {
        Ok(self
            .tree
            .root()
            .ok_or_else(|| FastCryptoError::GeneralError("Tree is empty".to_string()))?)
    }
}

/// A proof
pub struct Proof<const DIGEST_LENGTH: usize, H: HashFunction<DIGEST_LENGTH>, T: AsRef<[u8]>> {
    proof: MerkleProof<InternalNodeHasher<DIGEST_LENGTH, H>>,
    _type: PhantomData<T>,
}

struct PrefixedHasher<const PREFIX: u8, const DIGEST_LENGTH: usize, H: HashFunction<DIGEST_LENGTH>>
{
    _hasher: PhantomData<H>,
}

impl<const PREFIX: u8, const DIGEST_LENGTH: usize, H: HashFunction<DIGEST_LENGTH>> Clone
    for PrefixedHasher<PREFIX, DIGEST_LENGTH, H>
{
    fn clone(&self) -> Self {
        Self {
            _hasher: PhantomData::default(),
        }
    }
}

impl<const PREFIX: u8, const DIGEST_LENGTH: usize, H: HashFunction<DIGEST_LENGTH>> Hasher
    for PrefixedHasher<PREFIX, DIGEST_LENGTH, H>
{
    type Hash = [u8; DIGEST_LENGTH];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut input = vec![];
        input.push(PREFIX);
        input.extend_from_slice(data);
        H::digest(input).digest
    }
}

/// Computes H(0x01 || X)
type InternalNodeHasher<const DIGEST_LENGTH: usize, H> = PrefixedHasher<0x01, DIGEST_LENGTH, H>;

/// Computes H(0x00 || X)
type LeafHasher<const DIGEST_LENGTH: usize, H> = PrefixedHasher<0x00, DIGEST_LENGTH, H>;

#[cfg(test)]
mod tests {
    use crate::merkle_tree::MerkleTree;
    use fastcrypto::hash::Sha256;

    #[test]
    fn test_merkle_tree() {
        let mut tree = MerkleTree::<32, Sha256, Vec<u8>>::new();

        let elements = [vec![1u8], vec![2u8], vec![3u8]];
        assert_eq!(0, tree.number_of_leaves());
        tree.insert_all(&elements);
        assert_eq!(3, tree.number_of_leaves());

        let root = tree.root();

        // Generate proof for a given element
        let index = 1;
        let element = &elements[index];

        let proof = tree.prove(index);

        let verifier = tree.create_verifier().unwrap();
        assert!(verifier.verify_with_element(index, element, &proof));

        // Adding
        tree.insert(&vec![4u8]);
        assert_ne!(root, tree.root());

        let verifier = tree.create_verifier().unwrap();
        assert!(!verifier.verify_with_element(index, element, &proof));
    }
}
