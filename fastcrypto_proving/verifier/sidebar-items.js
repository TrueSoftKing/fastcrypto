window.SIDEBAR_ITEMS = {"fn":[["log_2_byte","Returns the log base 2 of b in O(lg(N)) time."],["process_vk_special","Takes an input Verifier key `vk` and returns a `SpecialPreparedVerifyingKey`. This is roughly homologous to [`ark_groth16::PreparedVerifyingKey::process_vk`]."],["verify_with_processed_vk","Returns the validity of the Groth16 proof passed as argument. The format of the inputs is assumed to be in arkworks format. See [`multipairing_with_processed_vk`] for the actual pairing computation details. TODO: due to arkworks incompatibilities in BLS12-381 point (de) serialization, we should probably implement a custom (de)serialization for those formats, see https://github.com/arkworks-rs/algebra/issues/257"]],"struct":[["PreparedVerifyingKey","This is a helper function to store a pre-processed version of the verifying key. This is roughly homologous to [`ark_groth16::PreparedVerifyingKey`]. Note that contrary to Arkworks, we don’t store a “prepared” version of the gamma_g2_neg_pc, delta_g2_neg_pc fields, because we can’t use them with blst’s pairing engine."],["Proof","A proof in the Groth16 SNARK."],["VerifyingKey","A verification key in the Groth16 SNARK."]]};