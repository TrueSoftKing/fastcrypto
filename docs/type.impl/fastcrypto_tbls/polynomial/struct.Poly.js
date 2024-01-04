(function() {var type_impls = {
"fastcrypto_tbls":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#30-37\">source</a><a href=\"#impl-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section></summary><div class=\"docblock\"><p>Vector related operations.</p>\n</div><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.degree\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#32-36\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.degree\" class=\"fn\">degree</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a></h4></section></summary><div class=\"docblock\"><p>Returns the degree of the polynomial</p>\n</div></details></div></details>",0,"fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#47-153\">source</a><a href=\"#impl-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C: GroupElement&gt; <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section></summary><div class=\"docblock\"><p>GroupElement operations.</p>\n</div><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.zero\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#49-51\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.zero\" class=\"fn\">zero</a>() -&gt; Self</h4></section></summary><div class=\"docblock\"><p>Returns a polynomial with the zero element.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.add\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#54-60\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.add\" class=\"fn\">add</a>(&amp;mut self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class=\"docblock\"><p>Performs polynomial addition in place.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.eval\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#67-80\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.eval\" class=\"fn\">eval</a>(&amp;self, i: <a class=\"type\" href=\"fastcrypto_tbls/types/type.ShareIndex.html\" title=\"type fastcrypto_tbls::types::ShareIndex\">ShareIndex</a>) -&gt; <a class=\"type\" href=\"fastcrypto_tbls/polynomial/type.Eval.html\" title=\"type fastcrypto_tbls::polynomial::Eval\">Eval</a>&lt;C&gt;</h4></section></summary><div class=\"docblock\"><p>Evaluates the polynomial at the specified value.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.recover_c0\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#120-131\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.recover_c0\" class=\"fn\">recover_c0</a>(\n    t: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>,\n    shares: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a>&lt;Item = impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html\" title=\"trait core::borrow::Borrow\">Borrow</a>&lt;<a class=\"type\" href=\"fastcrypto_tbls/polynomial/type.Eval.html\" title=\"type fastcrypto_tbls::polynomial::Eval\">Eval</a>&lt;C&gt;&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;C, FastCryptoError&gt;</h4></section></summary><div class=\"docblock\"><p>Given exactly <code>t</code> polynomial evaluations, it will recover the polynomial’s constant term.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.verify_share\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#134-142\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.verify_share\" class=\"fn\">verify_share</a>(\n    &amp;self,\n    idx: <a class=\"type\" href=\"fastcrypto_tbls/types/type.ShareIndex.html\" title=\"type fastcrypto_tbls::types::ShareIndex\">ShareIndex</a>,\n    share: &amp;C::ScalarType\n) -&gt; FastCryptoResult&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Checks if a given share is valid.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.c0\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#145-147\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.c0\" class=\"fn\">c0</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;C</a></h4></section></summary><div class=\"docblock\"><p>Return the constant term of the polynomial.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.as_vec\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#150-152\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.as_vec\" class=\"fn\">as_vec</a>(&amp;self) -&gt; &amp;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;C&gt;</h4></section></summary><div class=\"docblock\"><p>Returns the coefficients of the polynomial.</p>\n</div></details></div></details>",0,"fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#157-177\">source</a><a href=\"#impl-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C: Scalar&gt; <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section></summary><div class=\"docblock\"><p>Scalar operations.</p>\n</div><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.rand\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#161-164\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.rand\" class=\"fn\">rand</a>&lt;R: AllowedRng&gt;(degree: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, rng: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut R</a>) -&gt; Self</h4></section></summary><div class=\"docblock\"><p>Returns a new polynomial of the given degree where each coefficients is\nsampled at random from the given RNG.\nIn the context of secret sharing, the threshold is the degree + 1.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.commit\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#168-176\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.commit\" class=\"fn\">commit</a>&lt;P: GroupElement&lt;ScalarType = C&gt;&gt;(&amp;self) -&gt; <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;P&gt;</h4></section></summary><div class=\"docblock\"><p>Commits the scalar polynomial to the group and returns a polynomial over\nthe group.</p>\n</div></details></div></details>",0,"fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#179-191\">source</a><a href=\"#impl-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C: GroupElement + MultiScalarMul&gt; <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.recover_c0_msm\" class=\"method\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#182-190\">source</a><h4 class=\"code-header\">pub fn <a href=\"fastcrypto_tbls/polynomial/struct.Poly.html#tymethod.recover_c0_msm\" class=\"fn\">recover_c0_msm</a>(\n    t: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>,\n    shares: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a>&lt;Item = impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html\" title=\"trait core::borrow::Borrow\">Borrow</a>&lt;<a class=\"type\" href=\"fastcrypto_tbls/polynomial/type.Eval.html\" title=\"type fastcrypto_tbls::polynomial::Eval\">Eval</a>&lt;C&gt;&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;C, FastCryptoError&gt;</h4></section></summary><div class=\"docblock\"><p>Given exactly <code>t</code> polynomial evaluations, it will recover the polynomial’s\nconstant term.</p>\n</div></details></div></details>",0,"fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#impl-Deserialize%3C'de%3E-for-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de, C&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(__deserializer: __D) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, __D::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</div></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.156/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#impl-Clone-for-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CVec%3CC%3E%3E-for-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#39-43\">source</a><a href=\"#impl-From%3CVec%3CC%3E%3E-for-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;C&gt;&gt; for <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#40-42\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(c: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;C&gt;) -&gt; Self</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<Vec<C>>","fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<section id=\"impl-StructuralPartialEq-for-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#impl-StructuralPartialEq-for-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section>","StructuralPartialEq","fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#impl-Serialize-for-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(&amp;self, __serializer: __S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;__S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, __S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.156/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<section id=\"impl-Eq-for-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#impl-Eq-for-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section>","Eq","fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#impl-PartialEq-for-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#242\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<section id=\"impl-StructuralEq-for-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#impl-StructuralEq-for-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralEq.html\" title=\"trait core::marker::StructuralEq\">StructuralEq</a> for <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section>","StructuralEq","fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-Poly%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#impl-Debug-for-Poly%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;C&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/polynomial.rs.html#22\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","fastcrypto_tbls::polynomial::PrivatePoly","fastcrypto_tbls::polynomial::PublicPoly"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()