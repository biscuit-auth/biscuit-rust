const wasm = require("wasm-bindgen-test.js");
const assert = require("assert");

exports.create_biscuit_with_fact_and_verify_it = () => {
    let keypair = wasm.keypair_new();

    let builder = wasm.BiscuitBuilderBind.new_with_default_symbol();
    let fact = wasm.fact_bind("right", [
        { Symbol: "authority" },
        { Str: "file1" },
        { Symbol: "read" }
    ]);
    builder.add_authority_fact(fact);

    fact = wasm.fact_bind("right", [
        { Symbol: "authority" },
        { Str: "file2" },
        { Symbol: "read" }
    ]);
    builder.add_authority_fact(fact);

    fact = wasm.fact_bind("right", [
        { Symbol: "authority" },
        { Str: "file1" },
        { Symbol: "write" }
    ]);
    builder.add_authority_fact(fact);

    let biscuit = builder.build(keypair);

    let verifier = new wasm.VerifierBind();
    verifier.add_resource("file2");
    verifier.add_operation("read");
    verifier.add_operation("write");

    let rule = wasm.rule_bind(
        "right",
        [{ Symbol: "right" }],
        [
        {
            name: "right",
            ids: [{ Symbol: "authority" }, { Str: "file2" }, { Symbol: "write" }]
        }
        ]
    );

    verifier.add_rule(rule);

    let res = verifier.verify(biscuit);
};
