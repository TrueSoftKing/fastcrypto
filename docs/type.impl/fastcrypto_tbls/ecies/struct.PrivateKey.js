(function() {var type_impls = {
"fastcrypto_tbls":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PrivateKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#50-82\">source</a><a href=\"#impl-PrivateKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G&gt; <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G: <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,\n    &lt;G as <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a>&gt;::<a class=\"associatedtype\" href=\"fastcrypto/groups/trait.GroupElement.html#associatedtype.ScalarType\" title=\"type fastcrypto::groups::GroupElement::ScalarType\">ScalarType</a>: <a class=\"trait\" href=\"fastcrypto/groups/trait.FiatShamirChallenge.html\" title=\"trait fastcrypto::groups::FiatShamirChallenge\">FiatShamirChallenge</a>,</span></h3></section></summary><div class=\"impl-items\"><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#55-57\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html#tymethod.new\" class=\"fn\">new</a>&lt;R: <a class=\"trait\" href=\"fastcrypto/traits/trait.AllowedRng.html\" title=\"trait fastcrypto::traits::AllowedRng\">AllowedRng</a>&gt;(rng: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut R</a>) -&gt; Self</h4></section><section id=\"method.from\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#59-61\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html#tymethod.from\" class=\"fn\">from</a>(sc: G::<a class=\"associatedtype\" href=\"fastcrypto/groups/trait.GroupElement.html#associatedtype.ScalarType\" title=\"type fastcrypto::groups::GroupElement::ScalarType\">ScalarType</a>) -&gt; Self</h4></section><section id=\"method.decrypt\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#63-65\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html#tymethod.decrypt\" class=\"fn\">decrypt</a>(&amp;self, enc: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.Encryption.html\" title=\"struct fastcrypto_tbls::ecies::Encryption\">Encryption</a>&lt;G&gt;) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;</h4></section><section id=\"method.create_recovery_package\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#67-81\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html#tymethod.create_recovery_package\" class=\"fn\">create_recovery_package</a>&lt;R: <a class=\"trait\" href=\"fastcrypto/traits/trait.AllowedRng.html\" title=\"trait fastcrypto::traits::AllowedRng\">AllowedRng</a>&gt;(\n    &amp;self,\n    enc: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.Encryption.html\" title=\"struct fastcrypto_tbls::ecies::Encryption\">Encryption</a>&lt;G&gt;,\n    random_oracle: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/random_oracle/struct.RandomOracle.html\" title=\"struct fastcrypto_tbls::random_oracle::RandomOracle\">RandomOracle</a>,\n    rng: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut R</a>\n) -&gt; <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.RecoveryPackage.html\" title=\"struct fastcrypto_tbls::ecies::RecoveryPackage\">RecoveryPackage</a>&lt;G&gt;</h4></section></div></details>",0,"fastcrypto_tbls::types::PrivateEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-PrivateKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#impl-Debug-for-PrivateKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G::<a class=\"associatedtype\" href=\"fastcrypto/groups/trait.GroupElement.html#associatedtype.ScalarType\" title=\"type fastcrypto::groups::GroupElement::ScalarType\">ScalarType</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","fastcrypto_tbls::types::PrivateEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-PrivateKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#impl-Serialize-for-PrivateKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G::<a class=\"associatedtype\" href=\"fastcrypto/groups/trait.GroupElement.html#associatedtype.ScalarType\" title=\"type fastcrypto::groups::GroupElement::ScalarType\">ScalarType</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(&amp;self, __serializer: __S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;__S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, __S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<span class=\"where fmt-newline\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</span></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","fastcrypto_tbls::types::PrivateEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-PrivateKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#impl-PartialEq-for-PrivateKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> + <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G::<a class=\"associatedtype\" href=\"fastcrypto/groups/trait.GroupElement.html#associatedtype.ScalarType\" title=\"type fastcrypto::groups::GroupElement::ScalarType\">ScalarType</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#239\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","fastcrypto_tbls::types::PrivateEciesKey"],["<section id=\"impl-StructuralPartialEq-for-PrivateKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#impl-StructuralPartialEq-for-PrivateKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;</h3></section>","StructuralPartialEq","fastcrypto_tbls::types::PrivateEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-PrivateKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#impl-Clone-for-PrivateKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G::<a class=\"associatedtype\" href=\"fastcrypto/groups/trait.GroupElement.html#associatedtype.ScalarType\" title=\"type fastcrypto::groups::GroupElement::ScalarType\">ScalarType</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","fastcrypto_tbls::types::PrivateEciesKey"],["<section id=\"impl-StructuralEq-for-PrivateKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#impl-StructuralEq-for-PrivateKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralEq.html\" title=\"trait core::marker::StructuralEq\">StructuralEq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;</h3></section>","StructuralEq","fastcrypto_tbls::types::PrivateEciesKey"],["<section id=\"impl-Eq-for-PrivateKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#impl-Eq-for-PrivateKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> + <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G::<a class=\"associatedtype\" href=\"fastcrypto/groups/trait.GroupElement.html#associatedtype.ScalarType\" title=\"type fastcrypto::groups::GroupElement::ScalarType\">ScalarType</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>,</span></h3></section>","Eq","fastcrypto_tbls::types::PrivateEciesKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-PrivateKey%3CG%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#impl-Deserialize%3C'de%3E-for-PrivateKey%3CG%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, G: <a class=\"trait\" href=\"fastcrypto/groups/trait.GroupElement.html\" title=\"trait fastcrypto::groups::GroupElement\">GroupElement</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"fastcrypto_tbls/ecies/struct.PrivateKey.html\" title=\"struct fastcrypto_tbls::ecies::PrivateKey\">PrivateKey</a>&lt;G&gt;<span class=\"where fmt-newline\">where\n    G::<a class=\"associatedtype\" href=\"fastcrypto/groups/trait.GroupElement.html#associatedtype.ScalarType\" title=\"type fastcrypto::groups::GroupElement::ScalarType\">ScalarType</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,</span></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/ecies.rs.html#26\">source</a><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(__deserializer: __D) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, __D::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<span class=\"where fmt-newline\">where\n    __D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</span></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","fastcrypto_tbls::types::PrivateEciesKey"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()