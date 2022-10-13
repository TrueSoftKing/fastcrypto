(function() {var implementors = {
"fastcrypto":[["impl&lt;N:&nbsp;ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;,</span>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/bls12381/struct.BLS12381KeyPair.html\" title=\"struct fastcrypto::bls12381::BLS12381KeyPair\">BLS12381KeyPair</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/bls12381/struct.BLS12381Signature.html\" title=\"struct fastcrypto::bls12381::BLS12381Signature\">BLS12381Signature</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/bls12381/struct.BLS12381AggregateSignature.html\" title=\"struct fastcrypto::bls12381::BLS12381AggregateSignature\">BLS12381AggregateSignature</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/bls12381/struct.BLS12381PublicKey.html\" title=\"struct fastcrypto::bls12381::BLS12381PublicKey\">BLS12381PublicKey</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/bls12381/struct.BLS12381PrivateKey.html\" title=\"struct fastcrypto::bls12381::BLS12381PrivateKey\">BLS12381PrivateKey</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/bulletproofs/struct.PedersenCommitment.html\" title=\"struct fastcrypto::bulletproofs::PedersenCommitment\">PedersenCommitment</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519KeyPair.html\" title=\"struct fastcrypto::ed25519::Ed25519KeyPair\">Ed25519KeyPair</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519AggregateSignature.html\" title=\"struct fastcrypto::ed25519::Ed25519AggregateSignature\">Ed25519AggregateSignature</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519PublicKey.html\" title=\"struct fastcrypto::ed25519::Ed25519PublicKey\">Ed25519PublicKey</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519PrivateKey.html\" title=\"struct fastcrypto::ed25519::Ed25519PrivateKey\">Ed25519PrivateKey</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519Signature.html\" title=\"struct fastcrypto::ed25519::Ed25519Signature\">Ed25519Signature</a>"],["impl&lt;const DIGEST_LEN:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/hash/struct.Digest.html\" title=\"struct fastcrypto::hash::Digest\">Digest</a>&lt;DIGEST_LEN&gt;"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1PublicKey.html\" title=\"struct fastcrypto::secp256k1::Secp256k1PublicKey\">Secp256k1PublicKey</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1PrivateKey.html\" title=\"struct fastcrypto::secp256k1::Secp256k1PrivateKey\">Secp256k1PrivateKey</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1Signature.html\" title=\"struct fastcrypto::secp256k1::Secp256k1Signature\">Secp256k1Signature</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1KeyPair.html\" title=\"struct fastcrypto::secp256k1::Secp256k1KeyPair\">Secp256k1KeyPair</a>"],["impl&lt;T, const N:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.145/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/pubkey_bytes/struct.PublicKeyBytes.html\" title=\"struct fastcrypto::pubkey_bytes::PublicKeyBytes\">PublicKeyBytes</a>&lt;T, N&gt;"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()