// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Module minimizing the size of signatures. See also [min_pk].

use super::*;
use crate::serde_helpers::min_sig::BlsSignature;
use blst::min_sig as blst;
/// Hash-to-curve domain separation tag.
pub const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
define_bls12381!(BLS_G2_LENGTH, BLS_G1_LENGTH, DST_G1);

#[cfg(feature = "experimental")]
pub mod mskr;

use ::blst::{blst_p1, blst_p2};
use ::blst::{blst_p1_affine, blst_p2_affine};
use ::blst::{blst_p1_deserialize, blst_p2_deserialize};
use ::blst::{blst_p1_from_affine, blst_p2_from_affine};
use ::blst::{blst_p1_mult, blst_p2_mult};
use ::blst::{blst_p1_serialize, blst_p2_serialize};
use once_cell::sync::OnceCell;

pub fn randomize_g1_signature(
    signature: &min_sig::BLS12381Signature,
    r: &blst_scalar,
) -> min_sig::BLS12381Signature {
    let sig_bytes = signature.sig.serialize();
    let mut serialized: [u8; 96] = [0; 96];

    unsafe {
        // Signature as affine point
        let mut pubkey_affine_pt = blst_p1_affine::default();
        blst_p1_deserialize(&mut pubkey_affine_pt, sig_bytes.as_ptr());

        // Signature as point
        let mut pubkey_pt = blst_p1::default();
        blst_p1_from_affine(&mut pubkey_pt, &pubkey_affine_pt);

        // Randomized signature as point
        let mut randomized_pt = blst_p1::default();
        blst_p1_mult(&mut randomized_pt, &pubkey_pt, &(r.b[0]), 256);

        // Serialize randomized signature
        blst_p1_serialize(serialized.as_mut_ptr(), &randomized_pt);
    }

    min_sig::BLS12381Signature {
        sig: self::blst::Signature::deserialize(&serialized).unwrap(),
        bytes: OnceCell::new(),
    }
}

pub fn randomize_g2_pk(
    pk: &min_sig::BLS12381PublicKey,
    r: &blst_scalar,
) -> min_sig::BLS12381PublicKey {
    let pubkey_bytes = pk.pubkey.serialize();
    let mut serialized: [u8; 192] = [0; 192];

    unsafe {
        // Public key as affine point
        let mut pubkey_affine_pt = blst_p2_affine::default();
        blst_p2_deserialize(&mut pubkey_affine_pt, pubkey_bytes.as_ptr());

        // Public key as point
        let mut pubkey_pt = blst_p2::default();
        blst_p2_from_affine(&mut pubkey_pt, &pubkey_affine_pt);

        // Randomization factor as scalar
        // let mut scalar = blst_scalar::default();
        // blst_scalar_from_fr(&mut scalar, r);

        // Randomized public key as point
        let mut randomized_pt = blst_p2::default();
        blst_p2_mult(&mut randomized_pt, &pubkey_pt, &(r.b[0]), 256);

        // Serialize randomized public key
        blst_p2_serialize(serialized.as_mut_ptr(), &randomized_pt);
    }
    BLS12381PublicKey {
        pubkey: self::blst::PublicKey::deserialize(&serialized).unwrap(),
        bytes: OnceCell::new(),
    }
}
