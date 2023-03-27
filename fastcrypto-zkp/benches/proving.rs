// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use ark_bls12_377::{Bls12_377, Fr as Bls377Fr};
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_bn254::{Bn254, Fr as Bn254Fr};

use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{Groth16, VerifyingKey};
use ark_std::rand::thread_rng;
use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion, SamplingMode,
};
use fastcrypto_zkp::dummy_circuits::DummyCircuit;
use std::ops::Mul;

#[path = "./conversions.rs"]
mod conversions;

#[path = "./utils.rs"]
mod utils;

fn bench_prove<F: PrimeField, E: Pairing<ScalarField = F>, M: Measurement>(
    grp: &mut BenchmarkGroup<M>,
) {
    static CONSTRAINTS: [usize; 5] = [8, 9, 10, 11, 12];

    for size in CONSTRAINTS.iter() {
        let rng = &mut thread_rng();
        let c = DummyCircuit::<F> {
            a: Some(<F>::rand(rng)),
            b: Some(<F>::rand(rng)),
            num_variables: 12,
            num_constraints: (1 << *size),
        };

        let (pk, _) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();

        grp.bench_with_input(
            BenchmarkId::new("Groth16 prove", *size),
            &(pk, c),
            |b, (pk, c)| {
                b.iter(|| Groth16::<E>::prove(pk, *c, rng).unwrap());
            },
        );
    }
}

fn bench_verify<F: PrimeField, E: Pairing<ScalarField = F>, M: Measurement>(
    grp: &mut BenchmarkGroup<M>,
) {
    static CONSTRAINTS: [usize; 5] = [8, 9, 10, 11, 12];

    for size in CONSTRAINTS.iter() {
        let rng = &mut thread_rng();
        let c = DummyCircuit::<F> {
            a: Some(<F>::rand(rng)),
            b: Some(<F>::rand(rng)),
            num_variables: 12,
            num_constraints: (1 << *size),
        };

        let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
        let proof = Groth16::<E>::prove(&pk, c, rng).unwrap();
        let v = c.a.unwrap().mul(c.b.unwrap());

        grp.bench_with_input(
            BenchmarkId::new("Groth16 process verifying key", *size),
            &vk,
            |b, vk| {
                b.iter(|| Groth16::<E>::process_vk(vk).unwrap());
            },
        );
        let pvk = Groth16::<E>::process_vk(&vk).unwrap();

        grp.bench_with_input(
            BenchmarkId::new("Groth16 verify with processed vk", *size),
            &(pvk, v),
            |b, (pvk, v)| {
                b.iter(|| Groth16::<E>::verify_with_processed_vk(pvk, &[*v], &proof).unwrap());
            },
        );

        grp.bench_with_input(
            BenchmarkId::new("Groth16 end-to-end verify", *size),
            &(vk, v),
            |b, (vk, v)| {
                b.iter(|| Groth16::<E>::verify(vk, &[*v], &proof).unwrap());
            },
        );
    }
}

// This benches the elusiv send-quadra circuits used for private on-chain transfers.
// This circuit has 14 public inputs and ~22.5k constraints. More info about the exact details of it
// can be found at https://github.com/elusiv-privacy/circuits
fn bench_verify_elusiv_circuit<M: Measurement>(grp: &mut BenchmarkGroup<M>) {
    // Vec of tuples where first is the proof bytes and second is the public input bytes
    let elusiv_sample_proofs = vec![
        (
            vec![
                200, 64, 110, 88, 230, 195, 25, 66, 155, 223, 68, 156, 112, 239, 125, 21, 119, 131,
                236, 21, 84, 225, 222, 253, 156, 248, 230, 171, 73, 162, 69, 35, 199, 44, 216, 48,
                118, 224, 3, 96, 243, 35, 128, 210, 151, 176, 133, 95, 246, 32, 98, 96, 100, 43,
                148, 106, 166, 177, 17, 219, 127, 251, 7, 25, 204, 56, 254, 230, 250, 221, 182,
                214, 238, 247, 98, 237, 206, 72, 96, 205, 90, 145, 130, 69, 60, 55, 226, 136, 237,
                23, 141, 214, 158, 141, 105, 144, 47, 111, 48, 254, 248, 14, 39, 71, 58, 67, 53,
                27, 11, 253, 4, 252, 147, 116, 139, 232, 233, 128, 225, 121, 154, 1, 64, 172, 252,
                118, 3, 23,
            ],
            vec![
                151, 80, 66, 28, 48, 215, 48, 191, 123, 198, 203, 155, 199, 225, 206, 235, 147,
                188, 242, 60, 165, 119, 201, 240, 112, 196, 92, 3, 159, 241, 50, 36, 170, 79, 90,
                251, 116, 184, 91, 52, 37, 22, 254, 136, 175, 51, 154, 156, 191, 243, 162, 97, 183,
                12, 116, 235, 253, 27, 99, 115, 59, 146, 242, 40, 64, 249, 48, 191, 239, 110, 179,
                50, 141, 95, 145, 40, 238, 157, 103, 128, 124, 138, 61, 37, 186, 72, 7, 254, 68,
                192, 141, 16, 88, 184, 52, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 125, 40, 198, 133, 246, 224, 5,
                103, 244, 188, 245, 155, 180, 187, 99, 139, 61, 240, 162, 71, 44, 115, 162, 6, 35,
                181, 127, 42, 40, 42, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 19, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
                24, 147, 104, 39, 148, 146, 124, 216, 97, 141, 175, 220, 237, 79, 84, 211, 34, 227,
                179, 102, 101, 135, 103, 101, 231, 126, 43, 129, 159, 103, 15, 28, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 34, 128, 232, 148, 0, 87, 62, 242, 247, 47, 231, 196, 102, 124,
                90, 209, 6, 227, 132, 21, 29, 166, 48, 218, 38, 197, 52, 170, 112, 158, 227, 27,
            ],
        ),
        (
            vec![
                20, 245, 104, 221, 130, 235, 123, 204, 177, 114, 10, 110, 46, 183, 48, 120, 9, 170,
                51, 85, 158, 26, 189, 62, 237, 16, 46, 203, 175, 122, 245, 47, 128, 87, 105, 124,
                179, 152, 174, 66, 22, 174, 55, 85, 1, 47, 128, 147, 202, 36, 183, 172, 26, 137,
                85, 39, 96, 39, 212, 31, 124, 4, 168, 13, 1, 33, 72, 218, 200, 115, 180, 44, 146,
                88, 182, 241, 65, 111, 36, 248, 138, 83, 92, 147, 174, 50, 206, 139, 56, 181, 15,
                123, 0, 238, 20, 11, 123, 58, 226, 125, 60, 189, 123, 74, 214, 222, 32, 75, 128,
                205, 200, 6, 68, 207, 105, 214, 219, 76, 6, 205, 20, 198, 213, 119, 205, 236, 13,
                21,
            ],
            vec![
                187, 105, 172, 219, 4, 178, 82, 24, 207, 213, 168, 195, 53, 95, 53, 171, 213, 192,
                159, 78, 251, 174, 158, 168, 44, 21, 120, 167, 161, 85, 87, 20, 36, 159, 7, 87, 95,
                30, 146, 132, 86, 227, 151, 100, 176, 167, 157, 142, 13, 251, 220, 165, 141, 225,
                145, 119, 207, 238, 113, 199, 253, 149, 78, 5, 119, 251, 160, 26, 10, 92, 220, 11,
                212, 148, 56, 59, 245, 100, 28, 234, 83, 163, 83, 83, 48, 131, 246, 220, 176, 116,
                72, 8, 79, 68, 105, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 125, 40, 198, 133, 246, 224, 5, 103, 244,
                188, 245, 155, 180, 187, 99, 139, 61, 240, 162, 71, 44, 115, 162, 6, 35, 181, 127,
                42, 40, 42, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 19, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 175, 11, 110,
                47, 171, 92, 39, 63, 36, 183, 61, 144, 105, 250, 193, 22, 180, 65, 101, 199, 47,
                151, 12, 147, 158, 66, 62, 51, 147, 86, 89, 34, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                249, 251, 64, 35, 242, 208, 188, 51, 106, 123, 236, 123, 93, 72, 26, 61, 110, 224,
                247, 245, 114, 29, 253, 212, 174, 130, 115, 44, 183, 49, 31, 23,
            ],
        ),
        (
            vec![
                236, 91, 49, 127, 222, 244, 249, 129, 164, 151, 42, 141, 155, 193, 89, 217, 168,
                224, 118, 236, 221, 161, 26, 151, 93, 157, 56, 170, 148, 171, 35, 6, 74, 249, 223,
                146, 53, 163, 100, 76, 244, 223, 219, 31, 91, 253, 60, 205, 244, 163, 230, 66, 14,
                217, 2, 191, 43, 184, 172, 186, 10, 42, 125, 43, 6, 217, 41, 196, 92, 229, 152,
                145, 53, 27, 34, 91, 140, 72, 188, 172, 196, 157, 80, 4, 157, 130, 107, 62, 196,
                163, 103, 110, 198, 71, 87, 133, 54, 177, 25, 254, 76, 130, 13, 46, 161, 61, 140,
                38, 78, 216, 146, 141, 11, 36, 100, 190, 226, 228, 141, 105, 211, 20, 227, 11, 151,
                144, 141, 13,
            ],
            vec![
                221, 4, 136, 15, 240, 159, 119, 125, 24, 38, 148, 93, 41, 191, 214, 107, 177, 221,
                98, 69, 11, 61, 234, 35, 220, 30, 16, 155, 47, 27, 223, 12, 67, 96, 237, 248, 39,
                234, 207, 43, 182, 186, 205, 117, 199, 57, 201, 146, 6, 148, 61, 177, 143, 77, 57,
                104, 231, 125, 159, 14, 219, 59, 137, 36, 203, 154, 117, 22, 135, 140, 59, 41, 208,
                60, 42, 248, 110, 88, 111, 100, 20, 34, 216, 57, 130, 38, 125, 245, 128, 75, 182,
                62, 199, 78, 149, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 125, 40, 198, 133, 246, 224, 5, 103, 244,
                188, 245, 155, 180, 187, 99, 139, 61, 240, 162, 71, 44, 115, 162, 6, 35, 181, 127,
                42, 40, 42, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 19, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 169, 171,
                236, 77, 148, 73, 191, 154, 2, 215, 159, 152, 71, 28, 59, 147, 227, 156, 206, 93,
                22, 115, 184, 215, 172, 197, 132, 118, 221, 17, 13, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 244, 219, 13, 39, 83, 98, 145, 231, 235, 244, 144, 28, 17, 249, 28, 155, 38,
                106, 123, 53, 109, 160, 122, 242, 182, 79, 204, 168, 136, 81, 4, 0,
            ],
        ),
        (
            vec![
                233, 169, 254, 78, 26, 176, 115, 85, 50, 200, 7, 222, 168, 113, 78, 204, 251, 97,
                227, 239, 72, 186, 85, 170, 194, 99, 7, 228, 95, 114, 34, 19, 61, 228, 165, 250,
                43, 85, 56, 176, 229, 239, 14, 59, 216, 57, 28, 149, 17, 208, 137, 215, 213, 126,
                32, 102, 203, 211, 131, 254, 66, 220, 137, 14, 169, 59, 176, 186, 40, 215, 112,
                241, 184, 14, 147, 84, 210, 83, 157, 79, 59, 153, 186, 224, 48, 22, 85, 218, 76,
                167, 147, 203, 127, 42, 66, 157, 185, 214, 162, 23, 66, 169, 118, 245, 40, 66, 60,
                190, 99, 87, 178, 169, 4, 243, 120, 171, 135, 149, 139, 188, 214, 239, 177, 212,
                69, 80, 56, 10,
            ],
            vec![
                92, 63, 57, 103, 79, 82, 176, 221, 212, 144, 2, 24, 31, 146, 216, 105, 23, 17, 53,
                253, 243, 153, 215, 54, 10, 2, 137, 103, 131, 73, 101, 31, 229, 177, 166, 242, 53,
                2, 204, 173, 133, 192, 46, 75, 134, 109, 6, 239, 117, 187, 254, 197, 179, 29, 166,
                60, 234, 179, 160, 37, 67, 125, 19, 28, 49, 220, 36, 93, 34, 181, 182, 251, 16,
                139, 42, 247, 168, 2, 182, 41, 71, 210, 7, 217, 33, 246, 194, 236, 110, 251, 59,
                243, 255, 33, 235, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 125, 40, 198, 133, 246, 224, 5, 103, 244,
                188, 245, 155, 180, 187, 99, 139, 61, 240, 162, 71, 44, 115, 162, 6, 35, 181, 127,
                42, 40, 42, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 19, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 82, 154,
                18, 241, 43, 96, 221, 208, 210, 81, 222, 13, 229, 222, 12, 106, 78, 34, 164, 54,
                42, 152, 159, 180, 123, 2, 33, 210, 34, 251, 9, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 197, 178, 116, 29, 115, 94, 83, 162, 154, 11, 29, 175, 242, 172, 236, 231, 140,
                156, 184, 253, 117, 37, 204, 157, 12, 22, 203, 146, 122, 189, 102, 11,
            ],
        ),
    ];

    let vk: VerifyingKey<Bn254> = ark_groth16::VerifyingKey {
        alpha_g1: utils::G1Affine_from_str_projective((
            "8057073471822347335074195152835286348058235024870127707965681971765888348219",
            "14493022634743109860560137600871299171677470588934003383462482807829968516757",
            "1",
        )),
        beta_g2: utils::G2Affine_from_str_projective((
            (
                "3572582736973115805854009786889644784414020463323864932822856731322980736092",
                "20796599916820806690555061040933219683613855446136615092456120794141344002056",
            ),
            (
                "6655819316204680004365614375508079580461146204424752037766280753854543388537",
                "21051385956744942198035008062816432434887289184811055343085396392904977398400",
            ),
            ("1", "0"),
        )),
        gamma_g2: utils::G2Affine_from_str_projective((
            (
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            ),
            (
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            ),
            ("1", "0"),
        )),
        delta_g2: utils::G2Affine_from_str_projective((
            (
                "11998653647826530912022227389593270429577129765091819606672414955204726946137",
                "12850197969502293778482300034606665950383830355768697463743623195959747528569",
            ),
            (
                "3371177482557063281015231215914240035716553874474070718078727302911297506634",
                "12667795686197095991004340383609552078675969789404912385920584439828198138754",
            ),
            ("1", "0"),
        )),
        gamma_abc_g1: [
            [
                "11423936163622682661315257948859256751456935745483672301927753823261895199269",
                "8106299131826030264309317289206035584499915702251874486285904804204850744645",
                "1",
            ],
            [
                "3101734373871983241904605625023311773791709350380811153571118050344636150719",
                "5892752048111020912174143187873113013528793690570548925602265811558514488885",
                "1",
            ],
            [
                "10476231653569587456624794227763775706638536733174066539315272867287760110504",
                "10966166298405300401399180388536732567182096690752823243070979263725671251842",
                "1",
            ],
            [
                "3616644883823724294840639617628786582022507076201411671428851342676842026051",
                "20036054300972762576589546578455562677975529109923089992859054028247449793275",
                "1",
            ],
            [
                "8922146185459718802170954039785431585338226940878465749467742893964332142463",
                "6543899100030899685821688665010402257161600764202006060926513825176262562594",
                "1",
            ],
            [
                "8838880056209295823278313283853562429175894016112442003934942661774390156254",
                "12827213619164270378479427160832201667918020494718807523503415302940668517033",
                "1",
            ],
            [
                "2830281053896850092944028355764636104294475011402565423874976766597400897579",
                "13415270586926186600118105749667385774136247571413308961986554361125375974552",
                "1",
            ],
            [
                "18596510315364411631453906928618372802526744665579937948378160099177646939132",
                "13639164510921866583928930414183864880892036368934098358398305969672652727368",
                "1",
            ],
            [
                "5166155439194150342865876104665292251058885686253625593517703833929767249773",
                "15776325379616919283841092402757993241658241305931554423955510623840777140969",
                "1",
            ],
            [
                "244871576834190719988785477479956000478101720979685216270364011881385785410",
                "5006539956367064800739393540924950096169041851058318954717373683020872268739",
                "1",
            ],
            [
                "3379906259197166810955208903373839920133048860227880343760386881009843909062",
                "20232197429675204807642408172750830052412585778140676948557231371164499652906",
                "1",
            ],
            [
                "5520775405859402378836749033719619657978092778322140710653552702896452870563",
                "2840091105079872357493316251142119838752629278546220113584117974897982339624",
                "1",
            ],
            [
                "520211872811929422003078090188660039184112525356441893145895540025777918752",
                "18510673159743652418577623905535570073301952222198134524503321213201497608215",
                "1",
            ],
            [
                "6431234738107765889030689757699276709534858281277744012577221575246765244517",
                "4178355859219522686761165914894952086513502987193412248095296044093289572534",
                "1",
            ],
            [
                "4759337634951432350348093011115687353434771991388975508607474262950775320629",
                "3583982358135750838996058092244844686884741536705305315993181569552518297411",
                "1",
            ],
        ]
        .into_iter()
        .map(|s| utils::G1Affine_from_str_projective((s[0], s[1], s[2])))
        .collect(),
    };

    grp.bench_with_input(
        BenchmarkId::new(
            "BN254-based Groth16 prepare vkey for elusiv send quadra circuit",
            "",
        ),
        &vk,
        |b, vk| {
            b.iter(|| fastcrypto_zkp::bn254::verifier::process_vk_special(vk));
        },
    );

    let pvk = fastcrypto_zkp::bn254::verifier::process_vk_special(&vk);
    let bytes = pvk.as_serialized().unwrap();
    let vk_gamma_abc_g1_bytes = &bytes[0];
    let alpha_g1_beta_g2_bytes = &bytes[1];
    let gamma_g2_neg_pc_bytes = &bytes[2];
    let delta_g2_neg_pc_bytes = &bytes[3];

    for (i, proof) in elusiv_sample_proofs.iter().enumerate() {
        grp.bench_with_input(
            BenchmarkId::new(
                "BN254-based Groth16 verify elusiv send quadra circuit proof with index ",
                i,
            ),
            &(
                vk_gamma_abc_g1_bytes,
                alpha_g1_beta_g2_bytes,
                gamma_g2_neg_pc_bytes,
                delta_g2_neg_pc_bytes,
                proof,
            ),
            |b,
             (
                vk_gamma_abc_g1_bytes,
                alpha_g1_beta_g2_bytes,
                gamma_g2_neg_pc_bytes,
                delta_g2_neg_pc_bytes,
                proof,
            )| {
                b.iter(|| {
                    fastcrypto_zkp::bn254::api::verify_groth16_in_bytes(
                        vk_gamma_abc_g1_bytes,
                        alpha_g1_beta_g2_bytes,
                        gamma_g2_neg_pc_bytes,
                        delta_g2_neg_pc_bytes,
                        &proof.1,
                        &proof.0,
                    )
                });
            },
        );
    }
}

fn bench_our_verify<M: Measurement>(grp: &mut BenchmarkGroup<M>) {
    static CONSTRAINTS: [usize; 5] = [8, 9, 10, 11, 12];

    for size in CONSTRAINTS.iter() {
        let rng = &mut thread_rng();
        let c = DummyCircuit::<BlsFr> {
            a: Some(<BlsFr>::rand(rng)),
            b: Some(<BlsFr>::rand(rng)),
            num_variables: 12,
            num_constraints: (1 << *size),
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
        let proof = Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap();
        let v = c.a.unwrap().mul(c.b.unwrap());

        grp.bench_with_input(
            BenchmarkId::new("BLST-based Groth16 process verifying key", *size),
            &vk,
            |b, vk| {
                b.iter(|| fastcrypto_zkp::bls12381::verifier::process_vk_special(vk));
            },
        );
        let pvk = fastcrypto_zkp::bls12381::verifier::process_vk_special(&vk);

        grp.bench_with_input(
            BenchmarkId::new("BLST-based Groth16 verify with processed vk", *size),
            &(pvk, v),
            |b, (pvk, v)| {
                b.iter(|| {
                    fastcrypto_zkp::bls12381::verifier::verify_with_processed_vk(pvk, &[*v], &proof)
                        .unwrap()
                });
            },
        );
    }
}

fn prove(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("BLS12-381 Proving");
    group.sampling_mode(SamplingMode::Flat); // This can take a *while*
    group.sample_size(10);
    bench_prove::<BlsFr, Bls12_381, _>(&mut group);
    group.finish();

    // Add fields and pairing engines here
    let mut group: BenchmarkGroup<_> = c.benchmark_group("BN254 Proving");
    group.sampling_mode(SamplingMode::Flat); // This can take a *while*
    group.sample_size(10);
    bench_prove::<Bn254Fr, Bn254, _>(&mut group);
    group.finish();

    let mut group: BenchmarkGroup<_> = c.benchmark_group("BLS12-377 Proving");
    group.sampling_mode(SamplingMode::Flat); // This can take a *while*
    group.sample_size(10);
    bench_prove::<Bls377Fr, Bls12_377, _>(&mut group);
    group.finish();
}

fn verify(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("BLS12-381 Verification");
    // Add fields and pairing engines here
    bench_verify::<BlsFr, Bls12_381, _>(&mut group);
    bench_our_verify(&mut group);
    group.finish();

    // Add fields and pairing engines here
    let mut group: BenchmarkGroup<_> = c.benchmark_group("BN254 Verification");
    bench_verify::<Bn254Fr, Bn254, _>(&mut group);
    group.finish();

    let mut group: BenchmarkGroup<_> = c.benchmark_group("BLS12-377 Verification");
    bench_verify::<Bls377Fr, Bls12_377, _>(&mut group);
    group.finish();

    let mut group: BenchmarkGroup<_> = c.benchmark_group("Elusiv Circuit Verification");
    bench_verify_elusiv_circuit::<_>(&mut group);
    group.finish();
}

criterion_group! {
    name = proving_benches;
    config = Criterion::default();
    targets =
       verify,
       prove,
}

criterion_main!(conversions::conversion_benches, proving_benches,);
