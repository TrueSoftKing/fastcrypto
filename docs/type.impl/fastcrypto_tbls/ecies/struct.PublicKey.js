(function() {var type_impls = {
"fastcrypto_tbls":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#86-117\">source</a><a href=\"#impl-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G&gt; <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G: GroupElement + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,\n    &lt;G as GroupElement&gt;::ScalarType: FiatShamirChallenge,</span></h3></section></summary><div class=\"impl-items\"><section id=\"method.from_private_key\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#91-93\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/ecies/struct.PublicKey.html#tymethod.from_private_key\" class=\"fn\">from_private_key</a>(sk: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;) -&gt; Self</h4></section><section id=\"method.encrypt\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#95-97\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/ecies/struct.PublicKey.html#tymethod.encrypt\" class=\"fn\">encrypt</a>&lt;R: AllowedRng&gt;(&amp;self, msg: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>], rng: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut R</a>) -&gt; <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.Encryption.html\" title=\"struct fastcrypto_tbls::ecies::Encryption\">Encryption</a>&lt;G&gt;</h4></section><section id=\"method.deterministic_encrypt\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#99-101\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/ecies/struct.PublicKey.html#tymethod.deterministic_encrypt\" class=\"fn\">deterministic_encrypt</a>(msg: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>], r_g: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;G</a>, r_x_g: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;G</a>) -&gt; <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.Encryption.html\" title=\"struct fastcrypto_tbls::ecies::Encryption\">Encryption</a>&lt;G&gt;</h4></section><section id=\"method.decrypt_with_recovery_package\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#103-112\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/ecies/struct.PublicKey.html#tymethod.decrypt_with_recovery_package\" class=\"fn\">decrypt_with_recovery_package</a>(\n    &amp;self,\n    pkg: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.RecoveryPackage.html\" title=\"struct fastcrypto_tbls::ecies::RecoveryPackage\">RecoveryPackage</a>&lt;G&gt;,\n    random_oracle: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/random_oracle/struct.RandomOracle.html\" title=\"struct fastcrypto_tbls::random_oracle::RandomOracle\">RandomOracle</a>,\n    enc: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.Encryption.html\" title=\"struct fastcrypto_tbls::ecies::Encryption\">Encryption</a>&lt;G&gt;\n) -&gt; FastCryptoResult&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt;</h4></section><section id=\"method.as_element\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#114-116\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/ecies/struct.PublicKey.html#tymethod.as_element\" class=\"fn\">as_element</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;G</a></h4></section></div></details>",0,"fastcrypto_tbls::types::PublicEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#impl-Debug-for-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + GroupElement&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","fastcrypto_tbls::types::PublicEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#impl-Clone-for-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + GroupElement&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","fastcrypto_tbls::types::PublicEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#impl-PartialEq-for-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> + GroupElement&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#239\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","fastcrypto_tbls::types::PublicEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#impl-Serialize-for-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + GroupElement,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(&amp;self, __serializer: __S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;__S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, __S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<span class=\"where fmt-newline\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</span></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","fastcrypto_tbls::types::PublicEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#impl-Deserialize%3C'de%3E-for-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, G&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; + GroupElement,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(__deserializer: __D) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, __D::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<span class=\"where fmt-newline\">where\n    __D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</span></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","fastcrypto_tbls::types::PublicEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CG%3E-for-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#119-123\">source</a><a href=\"#impl-From%3CG%3E-for-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: GroupElement&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;G&gt; for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#120-122\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(p: G) -&gt; Self</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<G>","fastcrypto_tbls::types::PublicEciesKey"],["<section id=\"impl-Eq-for-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#impl-Eq-for-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + GroupElement&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;</h3></section>","Eq","fastcrypto_tbls::types::PublicEciesKey"],["<section id=\"impl-StructuralPartialEq-for-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#impl-StructuralPartialEq-for-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: GroupElement&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;</h3></section>","StructuralPartialEq","fastcrypto_tbls::types::PublicEciesKey"],["<section id=\"impl-StructuralEq-for-PublicKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#31\">source</a><a href=\"#impl-StructuralEq-for-PublicKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: GroupElement&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralEq.html\" title=\"trait core::marker::StructuralEq\">StructuralEq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PublicKey.html\" title=\"struct fastcrypto_tbls::ecies::PublicKey\">PublicKey</a>&lt;G&gt;</h3></section>","StructuralEq","fastcrypto_tbls::types::PublicEciesKey"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()