(function() {var implementors = {
"fastcrypto":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/bls12381/min_pk/struct.BLS12381AggregateSignature.html\" title=\"struct fastcrypto::bls12381::min_pk::BLS12381AggregateSignature\">BLS12381AggregateSignature</a>&gt; for <a class=\"struct\" href=\"fastcrypto/serde_helpers/struct.BytesRepresentation.html\" title=\"struct fastcrypto::serde_helpers::BytesRepresentation\">BytesRepresentation</a>&lt;{ BLS_G2_LENGTH }&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1Signature.html\" title=\"struct fastcrypto::secp256k1::Secp256k1Signature\">Secp256k1Signature</a>&gt; for <a class=\"struct\" href=\"fastcrypto/serde_helpers/struct.BytesRepresentation.html\" title=\"struct fastcrypto::serde_helpers::BytesRepresentation\">BytesRepresentation</a>&lt;SECP256K1_SIGNATURE_LENGTH&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/groups/bls12381/struct.G2Element.html\" title=\"struct fastcrypto::groups::bls12381::G2Element\">G2Element</a>&gt; for <a class=\"struct\" href=\"fastcrypto/serde_helpers/struct.BytesRepresentation.html\" title=\"struct fastcrypto::serde_helpers::BytesRepresentation\">BytesRepresentation</a>&lt;G2_ELEMENT_BYTE_LENGTH&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/ed25519-consensus/2.1.0/ed25519_consensus/signing_key/struct.SigningKey.html\" title=\"struct ed25519_consensus::signing_key::SigningKey\">SigningKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519KeyPair.html\" title=\"struct fastcrypto::ed25519::Ed25519KeyPair\">Ed25519KeyPair</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/curve25519-dalek-ng/4.1.1/curve25519_dalek_ng/scalar/struct.Scalar.html\" title=\"struct curve25519_dalek_ng::scalar::Scalar\">Scalar</a>&gt; for <a class=\"struct\" href=\"fastcrypto/groups/ristretto255/struct.RistrettoScalar.html\" title=\"struct fastcrypto::groups::ristretto255::RistrettoScalar\">RistrettoScalar</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"fastcrypto/bls12381/min_sig/struct.BLS12381Signature.html\" title=\"struct fastcrypto::bls12381::min_sig::BLS12381Signature\">BLS12381Signature</a>&gt; for <a class=\"struct\" href=\"fastcrypto/bls12381/min_sig/struct.BLS12381AggregateSignature.html\" title=\"struct fastcrypto::bls12381::min_sig::BLS12381AggregateSignature\">BLS12381AggregateSignature</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/secp256k1/recoverable/struct.Secp256k1RecoverableSignature.html\" title=\"struct fastcrypto::secp256k1::recoverable::Secp256k1RecoverableSignature\">Secp256k1RecoverableSignature</a>&gt; for <a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1Signature.html\" title=\"struct fastcrypto::secp256k1::Secp256k1Signature\">Secp256k1Signature</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/bls12381/min_sig/struct.BLS12381AggregateSignature.html\" title=\"struct fastcrypto::bls12381::min_sig::BLS12381AggregateSignature\">BLS12381AggregateSignature</a>&gt; for <a class=\"struct\" href=\"fastcrypto/serde_helpers/struct.BytesRepresentation.html\" title=\"struct fastcrypto::serde_helpers::BytesRepresentation\">BytesRepresentation</a>&lt;{ BLS_G1_LENGTH }&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>&gt; for <a class=\"struct\" href=\"fastcrypto/groups/bls12381/struct.Scalar.html\" title=\"struct fastcrypto::groups::bls12381::Scalar\">Scalar</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;blst_fr&gt; for <a class=\"struct\" href=\"fastcrypto/groups/bls12381/struct.Scalar.html\" title=\"struct fastcrypto::groups::bls12381::Scalar\">Scalar</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"fastcrypto/bls12381/min_pk/struct.BLS12381PrivateKey.html\" title=\"struct fastcrypto::bls12381::min_pk::BLS12381PrivateKey\">BLS12381PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/bls12381/min_pk/struct.BLS12381KeyPair.html\" title=\"struct fastcrypto::bls12381::min_pk::BLS12381KeyPair\">BLS12381KeyPair</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"fastcrypto/bls12381/min_sig/struct.BLS12381PrivateKey.html\" title=\"struct fastcrypto::bls12381::min_sig::BLS12381PrivateKey\">BLS12381PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/bls12381/min_sig/struct.BLS12381KeyPair.html\" title=\"struct fastcrypto::bls12381::min_sig::BLS12381KeyPair\">BLS12381KeyPair</a>"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'a <a class=\"struct\" href=\"fastcrypto/bls12381/min_pk/struct.BLS12381PrivateKey.html\" title=\"struct fastcrypto::bls12381::min_pk::BLS12381PrivateKey\">BLS12381PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/bls12381/min_pk/struct.BLS12381PublicKey.html\" title=\"struct fastcrypto::bls12381::min_pk::BLS12381PublicKey\">BLS12381PublicKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"fastcrypto/vrf/ecvrf/struct.ECVRFPrivateKey.html\" title=\"struct fastcrypto::vrf::ecvrf::ECVRFPrivateKey\">ECVRFPrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/vrf/ecvrf/struct.ECVRFKeyPair.html\" title=\"struct fastcrypto::vrf::ecvrf::ECVRFKeyPair\">ECVRFKeyPair</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/curve25519-dalek-ng/4.1.1/curve25519_dalek_ng/ristretto/struct.RistrettoPoint.html\" title=\"struct curve25519_dalek_ng::ristretto::RistrettoPoint\">RistrettoPoint</a>&gt; for <a class=\"struct\" href=\"fastcrypto/groups/ristretto255/struct.RistrettoPoint.html\" title=\"struct fastcrypto::groups::ristretto255::RistrettoPoint\">RistrettoPoint</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"fastcrypto/secp256r1/struct.Secp256r1PrivateKey.html\" title=\"struct fastcrypto::secp256r1::Secp256r1PrivateKey\">Secp256r1PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/secp256r1/struct.Secp256r1KeyPair.html\" title=\"struct fastcrypto::secp256r1::Secp256r1KeyPair\">Secp256r1KeyPair</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;blst_fp12&gt; for <a class=\"struct\" href=\"fastcrypto/groups/bls12381/struct.GTElement.html\" title=\"struct fastcrypto::groups::bls12381::GTElement\">GTElement</a>"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'a <a class=\"struct\" href=\"fastcrypto/secp256r1/struct.Secp256r1PrivateKey.html\" title=\"struct fastcrypto::secp256r1::Secp256r1PrivateKey\">Secp256r1PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/secp256r1/struct.Secp256r1PublicKey.html\" title=\"struct fastcrypto::secp256r1::Secp256r1PublicKey\">Secp256r1PublicKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;blst_p2&gt; for <a class=\"struct\" href=\"fastcrypto/groups/bls12381/struct.G2Element.html\" title=\"struct fastcrypto::groups::bls12381::G2Element\">G2Element</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/secp256r1/struct.Secp256r1Signature.html\" title=\"struct fastcrypto::secp256r1::Secp256r1Signature\">Secp256r1Signature</a>&gt; for <a class=\"struct\" href=\"fastcrypto/serde_helpers/struct.BytesRepresentation.html\" title=\"struct fastcrypto::serde_helpers::BytesRepresentation\">BytesRepresentation</a>&lt;SECP256R1_SIGNATURE_LENTH&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/groups/bls12381/struct.G1Element.html\" title=\"struct fastcrypto::groups::bls12381::G1Element\">G1Element</a>&gt; for <a class=\"struct\" href=\"fastcrypto/serde_helpers/struct.BytesRepresentation.html\" title=\"struct fastcrypto::serde_helpers::BytesRepresentation\">BytesRepresentation</a>&lt;G1_ELEMENT_BYTE_LENGTH&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/bls12381/min_pk/struct.BLS12381PublicKey.html\" title=\"struct fastcrypto::bls12381::min_pk::BLS12381PublicKey\">BLS12381PublicKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/serde_helpers/struct.BytesRepresentation.html\" title=\"struct fastcrypto::serde_helpers::BytesRepresentation\">BytesRepresentation</a>&lt;{ BLS_G1_LENGTH }&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/secp256r1/recoverable/struct.Secp256r1RecoverableSignature.html\" title=\"struct fastcrypto::secp256r1::recoverable::Secp256r1RecoverableSignature\">Secp256r1RecoverableSignature</a>&gt; for <a class=\"struct\" href=\"fastcrypto/secp256r1/struct.Secp256r1Signature.html\" title=\"struct fastcrypto::secp256r1::Secp256r1Signature\">Secp256r1Signature</a>"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'a <a class=\"struct\" href=\"fastcrypto/bls12381/min_sig/struct.BLS12381PrivateKey.html\" title=\"struct fastcrypto::bls12381::min_sig::BLS12381PrivateKey\">BLS12381PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/bls12381/min_sig/struct.BLS12381PublicKey.html\" title=\"struct fastcrypto::bls12381::min_sig::BLS12381PublicKey\">BLS12381PublicKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"fastcrypto/bls12381/min_pk/struct.BLS12381Signature.html\" title=\"struct fastcrypto::bls12381::min_pk::BLS12381Signature\">BLS12381Signature</a>&gt; for <a class=\"struct\" href=\"fastcrypto/bls12381/min_pk/struct.BLS12381AggregateSignature.html\" title=\"struct fastcrypto::bls12381::min_pk::BLS12381AggregateSignature\">BLS12381AggregateSignature</a>"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'a <a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519PrivateKey.html\" title=\"struct fastcrypto::ed25519::Ed25519PrivateKey\">Ed25519PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519PublicKey.html\" title=\"struct fastcrypto::ed25519::Ed25519PublicKey\">Ed25519PublicKey</a>"],["impl&lt;const DIGEST_LEN: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"fastcrypto/hash/struct.Digest.html\" title=\"struct fastcrypto::hash::Digest\">Digest</a>&lt;DIGEST_LEN&gt;&gt; for [<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.array.html\">DIGEST_LEN</a>]"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1PrivateKey.html\" title=\"struct fastcrypto::secp256k1::Secp256k1PrivateKey\">Secp256k1PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1KeyPair.html\" title=\"struct fastcrypto::secp256k1::Secp256k1KeyPair\">Secp256k1KeyPair</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/bls12381/min_sig/struct.BLS12381PublicKey.html\" title=\"struct fastcrypto::bls12381::min_sig::BLS12381PublicKey\">BLS12381PublicKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/serde_helpers/struct.BytesRepresentation.html\" title=\"struct fastcrypto::serde_helpers::BytesRepresentation\">BytesRepresentation</a>&lt;{ BLS_G2_LENGTH }&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"fastcrypto/error/enum.FastCryptoError.html\" title=\"enum fastcrypto::error::FastCryptoError\">FastCryptoError</a>"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'a <a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1PrivateKey.html\" title=\"struct fastcrypto::secp256k1::Secp256k1PrivateKey\">Secp256k1PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/secp256k1/struct.Secp256k1PublicKey.html\" title=\"struct fastcrypto::secp256k1::Secp256k1PublicKey\">Secp256k1PublicKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519PrivateKey.html\" title=\"struct fastcrypto::ed25519::Ed25519PrivateKey\">Ed25519PrivateKey</a>&gt; for <a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519KeyPair.html\" title=\"struct fastcrypto::ed25519::Ed25519KeyPair\">Ed25519KeyPair</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;blst_p1&gt; for <a class=\"struct\" href=\"fastcrypto/groups/bls12381/struct.G1Element.html\" title=\"struct fastcrypto::groups::bls12381::G1Element\">G1Element</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>&gt; for <a class=\"struct\" href=\"fastcrypto/groups/ristretto255/struct.RistrettoScalar.html\" title=\"struct fastcrypto::groups::ristretto255::RistrettoScalar\">RistrettoScalar</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"struct\" href=\"fastcrypto/ed25519/struct.Ed25519Signature.html\" title=\"struct fastcrypto::ed25519::Ed25519Signature\">Ed25519Signature</a>&gt; for <a class=\"struct\" href=\"fastcrypto/serde_helpers/struct.BytesRepresentation.html\" title=\"struct fastcrypto::serde_helpers::BytesRepresentation\">BytesRepresentation</a>&lt;ED25519_SIGNATURE_LENGTH&gt;"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()