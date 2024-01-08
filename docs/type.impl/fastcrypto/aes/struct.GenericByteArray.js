(function() {var type_impls = {
"fastcrypto":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Zeroize-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#127-134\">source</a><a href=\"#impl-Zeroize-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N&gt; Zeroize for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;<div class=\"where\">where\n    N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.zeroize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#131-133\">source</a><a href=\"#method.zeroize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">zeroize</a>(&amp;mut self)</h4></section></summary><div class='docblock'>Zero out this object from memory using Rust intrinsics which ensure the\nzeroization operation is not “optimized away” by the compiler.</div></details></div></details>","Zeroize","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-ToFromBytes-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#98-114\">source</a><a href=\"#impl-ToFromBytes-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N&gt; <a class=\"trait\" href=\"fastcrypto/traits/trait.ToFromBytes.html\" title=\"trait fastcrypto::traits::ToFromBytes\">ToFromBytes</a> for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;<div class=\"where\">where\n    N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from_bytes\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#102-109\">source</a><a href=\"#method.from_bytes\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto/traits/trait.ToFromBytes.html#tymethod.from_bytes\" class=\"fn\">from_bytes</a>(bytes: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>]) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, <a class=\"enum\" href=\"fastcrypto/error/enum.FastCryptoError.html\" title=\"enum fastcrypto::error::FastCryptoError\">FastCryptoError</a>&gt;</h4></section></summary><div class='docblock'>Parse an object from its byte representation</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.as_bytes\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#111-113\">source</a><a href=\"#method.as_bytes\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto/traits/trait.ToFromBytes.html#method.as_bytes\" class=\"fn\">as_bytes</a>(&amp;self) -&gt; &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>] <a href=\"#\" class=\"tooltip\" data-notable-ty=\"&amp;[u8]\">ⓘ</a></h4></section></summary><div class='docblock'>Borrow a byte slice representing the serialized form of this object</div></details></div></details>","ToFromBytes","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#impl-Clone-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Generate-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#116-125\">source</a><a href=\"#impl-Generate-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N&gt; <a class=\"trait\" href=\"fastcrypto/traits/trait.Generate.html\" title=\"trait fastcrypto::traits::Generate\">Generate</a> for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;<div class=\"where\">where\n    N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.generate\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#120-124\">source</a><a href=\"#method.generate\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto/traits/trait.Generate.html#tymethod.generate\" class=\"fn\">generate</a>&lt;R: <a class=\"trait\" href=\"fastcrypto/traits/trait.AllowedRng.html\" title=\"trait fastcrypto::traits::AllowedRng\">AllowedRng</a>&gt;(rng: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut R</a>) -&gt; <a class=\"type\" href=\"fastcrypto/aes/type.AesKey.html\" title=\"type fastcrypto::aes::AesKey\">AesKey</a>&lt;N&gt;</h4></section></summary><div class='docblock'>Generate a new random instance using the given RNG.</div></details></div></details>","Generate","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<section id=\"impl-ZeroizeOnDrop-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#impl-ZeroizeOnDrop-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt; ZeroizeOnDrop for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;</h3></section>","ZeroizeOnDrop","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#impl-Deserialize%3C'de%3E-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, N&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;<div class=\"where\">where\n    N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(__deserializer: __D) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, __D::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</div></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Display-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#impl-Display-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Display.html\" title=\"trait core::fmt::Display\">Display</a> for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Display.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Display.html#tymethod.fmt\">Read more</a></div></details></div></details>","Display","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#impl-Debug-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#impl-Serialize-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;<div class=\"where\">where\n    N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(&amp;self, __serializer: __S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;__S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, __S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Drop-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#impl-Drop-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.drop\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#85\">source</a><a href=\"#method.drop\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/ops/drop/trait.Drop.html#tymethod.drop\" class=\"fn\">drop</a>(&amp;mut self)</h4></section></summary><div class='docblock'>Executes the destructor for this type. <a href=\"https://doc.rust-lang.org/nightly/core/ops/drop/trait.Drop.html#tymethod.drop\">Read more</a></div></details></div></details>","Drop","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-AsRef%3C%5Bu8%5D%3E-for-GenericByteArray%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#92-96\">source</a><a href=\"#impl-AsRef%3C%5Bu8%5D%3E-for-GenericByteArray%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;N: ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"fastcrypto/aes/struct.GenericByteArray.html\" title=\"struct fastcrypto::aes::GenericByteArray\">GenericByteArray</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.as_ref\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto/aes.rs.html#93-95\">source</a><a href=\"#method.as_ref\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html#tymethod.as_ref\" class=\"fn\">as_ref</a>(&amp;self) -&gt; &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>] <a href=\"#\" class=\"tooltip\" data-notable-ty=\"&amp;[u8]\">ⓘ</a></h4></section></summary><div class='docblock'>Converts this type into a shared reference of the (usually inferred) input type.</div></details></div></details>","AsRef<[u8]>","fastcrypto::aes::AesKey","fastcrypto::aes::InitializationVector"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()