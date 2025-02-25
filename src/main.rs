extern crate ark_bn254;
extern crate rust_kzg_bn254_primitives;
extern crate rust_kzg_bn254_verifier;
extern crate anyhow;
extern crate hokulea_cryptography;
extern crate num;
extern crate rust_kzg_bn254_prover;
extern crate alloy_primitives;
extern crate ark_ff;

use std::time::Instant;
use alloy_primitives::Bytes;
use anyhow::anyhow;
use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use hokulea_cryptography::witness::EigenDABlobWitness;
use num::BigUint;
use rust_kzg_bn254_primitives::blob::Blob;
use rust_kzg_bn254_prover::kzg::KZG;
use rust_kzg_bn254_prover::srs::SRS;
use rust_kzg_bn254_verifier::batch;
use rust_kzg_bn254_verifier::batch::verify_blob_kzg_proof_batch;

fn main() {
    println!("Hello, world!");
    let mut eigenda_blobs = Vec::new();
    let mut commitments= Vec::new();
    let mut proofs = Vec::new();
    // let eigen_blobs: Vec<Blob> = Vec::new();
    // let eigen_commitments: Vec<G1Affine> = Vec::new();
    // let eigen_proofs: Vec<G1Affine> = Vec::new();
    // let result = verify_blob_kzg_proof_batch(&eigen_blobs, &eigen_commitments, &eigen_proofs)
    //     .map_err(|e| anyhow!("blob verification failed for batch: {:?}", e)).unwrap();
    let start = Instant::now();
    let v = vec![0u8; 512];
    let srs = SRS::new("resources/g1.32mb.point", 268435456, 50000).unwrap();
    let mut kzg = KZG::new();

    let input = Blob::new(&v);
    let input_poly = input.to_polynomial_eval_form();

    kzg.calculate_and_store_roots_of_unity(v.len() as u64).unwrap();

    let mut commitment_bytes = vec![0u8; 0];

    let commitment = kzg.commit_eval_form(&input_poly, &srs).unwrap();

    // TODO the library should have returned the bytes, or provide a helper
    // for conversion. For both proof and commitment
    let commitment_x_bigint: BigUint = commitment.x.into();
    let commitment_y_bigint: BigUint = commitment.y.into();

    append_left_padded_biguint_be(&mut commitment_bytes, &commitment_x_bigint);
    append_left_padded_biguint_be(&mut commitment_bytes, &commitment_y_bigint);

    let mut proof_bytes = vec![0u8; 0];

    let proof = kzg.compute_blob_proof(&input, &commitment, &srs).unwrap();
    let proof_x_bigint: BigUint = proof.x.into();
    let proof_y_bigint: BigUint = proof.y.into();

    append_left_padded_biguint_be(&mut proof_bytes, &proof_x_bigint);
    append_left_padded_biguint_be(&mut proof_bytes, &proof_y_bigint);
    let duration = start.elapsed();
    println!("Proof duration: {:?}", duration);

    let start_proof = Instant::now();
    // push data into witness
    // self.write(Bytes::copy_from_slice(blob), Bytes::copy_from_slice(&commitment_bytes), proof_bytes.into());
    eigenda_blobs.push(Bytes::copy_from_slice(&v));
    commitments.push(Bytes::copy_from_slice(&commitment_bytes));
    proofs.push(Bytes::copy_from_slice(&proof_bytes));
    let lib_blobs: Vec<Blob> = eigenda_blobs.iter().map(|b| Blob::new(b)).collect();
    let lib_commitments: Vec<G1Affine> = commitments
        .iter()
        .map(|c| {
            let x = Fq::from_be_bytes_mod_order(&c[..32]);
            let y = Fq::from_be_bytes_mod_order(&c[32..64]);
            G1Affine::new(x, y)
        })
        .collect();
    let lib_proofs: Vec<G1Affine> = proofs
        .iter()
        .map(|p| {
            let x = Fq::from_be_bytes_mod_order(&p[..32]);
            let y = Fq::from_be_bytes_mod_order(&p[32..64]);

            G1Affine::new(x, y)
        })
        .collect();
    let pairing_result = batch::verify_blob_kzg_proof_batch(&lib_blobs, &lib_commitments, &lib_proofs).unwrap();
    let duration_proof = start_proof.elapsed();
    println!("Proof verification result is: {:?}", pairing_result);
    println!("Proof verification duration: {:?}", duration_proof);

    // println!("result: {:?}", last_commitment);
}

pub fn append_left_padded_biguint_be(vec: &mut Vec<u8>, biguint: &BigUint) {
    let bytes = biguint.to_bytes_be();
    let padding = 32 - bytes.len();
    vec.extend(std::iter::repeat(0).take(padding));
    vec.extend_from_slice(&bytes);
}