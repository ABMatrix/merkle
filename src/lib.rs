// Copyright 2018 Chainpool

extern crate serialization as ser;
extern crate chain;
extern crate bit_vec;
extern crate primitives;
extern crate sr_std as rstd;

use self::ser::{Serializable, Deserializable, Stream, Reader};
use self::chain::merkle_node_hash;
use self::bit_vec::BitVec;
use self::primitives::hash::H256;
use self::primitives::io;
use self::rstd::cmp::min;
use self::rstd::prelude::Vec;

/// Partial merkle tree
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Clone)]
pub struct PartialMerkleTree {
    /// Total number of transactions
    pub tx_count: u32,
    /// Nodes hashes
    pub hashes: Vec<H256>,
    /// Match flags
    pub flags: BitVec,
}

impl Serializable for PartialMerkleTree {
    fn serialize(&self, stream: &mut Stream) {
        stream
			.append(&self.tx_count)
			.append_list(&self.hashes)
			// to_bytes() converts [true, false, true] to 0b10100000
			// while protocol requires [true, false, true] to be serialized as 0x00000101
			.append_list(&self.flags.to_bytes().into_iter()
				.map(|b|
					((b & 0b10000000) >> 7) |
						((b & 0b01000000) >> 5) |
						((b & 0b00100000) >> 3) |
						((b & 0b00010000) >> 1) |
						((b & 0b00001000) << 1) |
						((b & 0b00000100) << 3) |
						((b & 0b00000010) << 5) |
						((b & 0b00000001) << 7)).collect::<Vec<u8>>());
    }
}

impl Deserializable for PartialMerkleTree {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, io::Error>
    where
        Self: Sized,
        T: io::Read,
    {
        Ok(PartialMerkleTree {
            tx_count: reader.read()?,
            hashes: reader.read_list()?,
            flags: {
                let flags_bytes: Vec<u8> = reader.read_list()?;
                BitVec::from_bytes(
                    &(flags_bytes
                          .into_iter()
                          .map(|b| {
                        ((b & 0b10000000) >> 7) | ((b & 0b01000000) >> 5) |
                            ((b & 0b00100000) >> 3) |
                            ((b & 0b00010000) >> 1) |
                            ((b & 0b00001000) << 1) |
                            ((b & 0b00000100) << 3) |
                            ((b & 0b00000010) << 5) |
                            ((b & 0b00000001) << 7)
                    })
                          .collect::<Vec<u8>>()),
                )
            },
        })
    }
}

/// Partial merkle tree parse result
pub struct ParsedPartialMerkleTree {
    /// Merkle root
    pub root: H256,
    /// Matched hashes
    pub hashes: Vec<H256>,
    /// Match flags
    pub flags: BitVec,
}

/// Build partial merkle tree
pub fn build_partial_merkle_tree(tx_hashes: Vec<H256>, tx_matches: BitVec) -> PartialMerkleTree {
    PartialMerkleTreeBuilder::build(tx_hashes, tx_matches)
}

pub enum Error {
    NOTX,
    SURPLUSHASH,
    NOTMATCH,
    ALLUSED,
    SAMEHASH,
}

/// Parse partial merkle tree
pub fn parse_partial_merkle_tree(
    tree: PartialMerkleTree,
) -> Result<ParsedPartialMerkleTree, Error> {
    PartialMerkleTreeBuilder::parse(tree)
}

/// Service structure to construct `merkleblock` message.
struct PartialMerkleTreeBuilder {
    /// All transactions length.
    all_len: u32,
    /// All transactions hashes.
    all_hashes: Vec<H256>,
    /// Match flags for all transactions.
    all_matches: BitVec,
    /// Partial hashes.
    hashes: Vec<H256>,
    /// Partial match flags.
    matches: BitVec,
}

impl PartialMerkleTree {
    /// Create new merkle tree with given data
    pub fn new(tx_count: u32, hashes: Vec<H256>, flags: BitVec) -> Self {
        PartialMerkleTree {
            tx_count: tx_count,
            hashes: hashes,
            flags: flags,
        }
    }
}

impl ParsedPartialMerkleTree {
    pub fn new(root: H256, hashes: Vec<H256>, flags: BitVec) -> Self {
        ParsedPartialMerkleTree {
            root: root,
            hashes: hashes,
            flags: flags,
        }
    }
}

impl PartialMerkleTreeBuilder {
    /// Build partial merkle tree as described here:
    /// https://bitcoin.org/en/developer-reference#creating-a-merkleblock-message
    pub fn build(all_hashes: Vec<H256>, all_matches: BitVec) -> PartialMerkleTree {
        let mut partial_merkle_tree = PartialMerkleTreeBuilder {
            all_len: all_hashes.len() as u32,
            all_hashes: all_hashes,
            all_matches: all_matches,
            hashes: Vec::new(),
            matches: BitVec::new(),
        };
        partial_merkle_tree.build_tree();
        PartialMerkleTree::new(
            partial_merkle_tree.all_len,
            partial_merkle_tree.hashes,
            partial_merkle_tree.matches,
        )
    }

    /// Parse partial merkle tree as described here:
    /// https://bitcoin.org/en/developer-reference#parsing-a-merkleblock-message
    pub fn parse(tree: PartialMerkleTree) -> Result<ParsedPartialMerkleTree, Error> {
        let mut partial_merkle_tree = PartialMerkleTreeBuilder {
            all_len: tree.tx_count,
            all_hashes: Vec::new(),
            all_matches: BitVec::from_elem(tree.tx_count as usize, false),
            hashes: tree.hashes,
            matches: tree.flags,
        };

        match partial_merkle_tree.parse_tree() {
            Ok(merkle_root) => Ok(ParsedPartialMerkleTree::new(
                merkle_root,
                partial_merkle_tree.all_hashes,
                partial_merkle_tree.all_matches,
            )),
            Err(s) => Err(s),
        }
    }

    fn build_tree(&mut self) {
        let tree_height = self.tree_height();
        self.build_branch(tree_height, 0)
    }

    fn parse_tree(&mut self) -> Result<H256, Error> {
        if self.all_len == 0 {
            return Err(Error::NOTX);
        }
        if self.hashes.len() > self.all_len as usize {
            return Err(Error::SURPLUSHASH);
        }
        if self.matches.len() < self.hashes.len() {
            return Err(Error::NOTMATCH);
        }

        // parse tree
        let mut matches_used = 0usize;
        let mut hashes_used = 0usize;
        let tree_height = self.tree_height();
        match self.parse_branch(tree_height, 0, &mut matches_used, &mut hashes_used) {
            Ok(merkle_root) => {
                if matches_used != self.matches.len() &&
                    {
                        let mut found_true = false;
                        for i in matches_used..self.matches.len() {
                            if self.matches[i] == true {
                                found_true = true;
                            }
                        }
                        found_true
                    }
                {
                    return Err(Error::NOTMATCH);
                }
                if hashes_used != self.hashes.len() {
                    return Err(Error::ALLUSED);
                }
                Ok(merkle_root)
            }
            Err(s) => Err(s),
        }
    }

    fn build_branch(&mut self, height: usize, pos: usize) {
        // determine whether this node is the parent of at least one matched txid
        let transactions_begin = pos << height;
        let transactions_end = min(self.all_len as usize, (pos + 1) << height);
        let flag = (transactions_begin..transactions_end).any(|idx| self.all_matches[idx]);
        // remember flag
        self.matches.push(flag);
        // proceeed with descendants
        if height == 0 || !flag {
            // we're at the leaf level || there is no match
            let hash = self.branch_hash(height, pos);
            self.hashes.push(hash);
        } else {
            // proceed with left child
            self.build_branch(height - 1, pos << 1);
            // proceed with right child if any
            if (pos << 1) + 1 < self.level_width(height - 1) {
                self.build_branch(height - 1, (pos << 1) + 1);
            }
        }
    }

    fn parse_branch(
        &mut self,
        height: usize,
        pos: usize,
        matches_used: &mut usize,
        hashes_used: &mut usize,
    ) -> Result<H256, Error> {
        if *matches_used >= self.matches.len() {
            return Err(Error::ALLUSED);
        }

        let flag = self.matches[*matches_used];
        *matches_used += 1;

        if height == 0 || !flag {
            // we're at the leaf level || there is no match
            if *hashes_used > self.hashes.len() {
                return Err(Error::ALLUSED);
            }

            // get node hash
            let ref hash = self.hashes[*hashes_used];
            *hashes_used += 1;

            // on leaf level && matched flag set => mark transaction as matched
            if height == 0 && flag {
                self.all_hashes.push(hash.clone());
                self.all_matches.set(pos, true);
            }

            Ok(hash.clone())
        } else {
            // proceed with left child
            match self.parse_branch(height - 1, pos << 1, matches_used, hashes_used) {
                Ok(left) => {
                    // proceed with right child if any
                    let has_right_child = (pos << 1) + 1 < self.level_width(height - 1);
                    let right = if has_right_child {
                        match self.parse_branch(
                            height - 1,
                            (pos << 1) + 1,
                            matches_used,
                            hashes_used,
                        ) {
                            Err(s) => return Err(s),
                            Ok(right) => right,
                        }
                    } else {
                        left.clone()
                    };

                    if has_right_child && left == right {
                        Err(Error::SAMEHASH)
                    } else {
                        Ok(merkle_node_hash(&left, &right))
                    }
                }
                Err(s) => Err(s),
            }
        }
    }

    fn tree_height(&self) -> usize {
        let mut height = 0usize;
        while self.level_width(height) > 1 {
            height += 1;
        }
        height
    }

    fn level_width(&self, height: usize) -> usize {
        (self.all_len as usize + (1 << height) - 1) >> height
    }

    fn branch_hash(&self, height: usize, pos: usize) -> H256 {
        if height == 0 {
            self.all_hashes[pos].clone()
        } else {
            let left = self.branch_hash(height - 1, pos << 1);
            let right = if (pos << 1) + 1 < self.level_width(height - 1) {
                self.branch_hash(height - 1, (pos << 1) + 1)
            } else {
                left.clone()
            };

            merkle_node_hash(&left, &right)
        }
    }
}
