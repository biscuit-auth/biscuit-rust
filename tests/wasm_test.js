const wasm = require("wasm-bindgen-test.js")
const assert = require("assert")

exports.create_biscuit_with_authority_fact_and_verify_should_fail_on_caveat = () => {
    let keypair = wasm.keypair_new()

    let builder = wasm.BiscuitBuilderBind.new_with_default_symbol()
    let fact = wasm.fact_bind("right", [
        { Symbol: "authority" },
        { Str: "file1" },
        { Symbol: "read" }
    ])
    builder.add_authority_fact(fact)

    fact = wasm.fact_bind("right", [
        { Symbol: "authority" },
        { Str: "file2" },
        { Symbol: "read" }
    ])
    builder.add_authority_fact(fact)

    fact = wasm.fact_bind("right", [
        { Symbol: "authority" },
        { Str: "file1" },
        { Symbol: "write" }
    ])
    builder.add_authority_fact(fact)

    let biscuit = builder.build(keypair)

    let keypair2 = wasm.keypair_new()
    let blockbuilder = biscuit.create_block()
    let block = blockbuilder.build()

    let biscuit2 = biscuit.append(keypair2, block)

    let verifier = new wasm.VerifierBind()
    let rule = wasm.rule_bind(
        "right",
        [{ Symbol: "right" }],
        [
        {
            name: "right",
            ids: [{ Symbol: "authority" }, { Str: "file2" }, { Symbol: "write" }]
        }
        ]
    )

    verifier.add_authority_caveats(rule)
    verifier.verify(biscuit2)
};

exports.create_block_with_authority_fact_and_verify = () => {
    let keypair = wasm.keypair_new()

    let authority_block = wasm.BlockBuilderBind.new_with_default_symbols();
    authority_block.add_fact(wasm.fact_bind("right", [ { Symbol: "authority" }, { Str: "file1" }, { Str: "read" } ] ))
    authority_block.add_fact(wasm.fact_bind("right", [ { Symbol: "authority" }, { Str: "file2" }, { Str: "read" } ] ))
    authority_block.add_fact(wasm.fact_bind("right", [ { Symbol: "authority" }, { Str: "file1" }, { Str: "write" } ] ))

    let biscuit1 = new wasm.BiscuitBinder(keypair, authority_block.build())

    let blockBuilder = biscuit1.create_block()

    let rules = wasm.rule_bind(
        "caveat1",
        [{ Variable: 0 }],
        [
            {
                name: "resource",
                ids: [{ Symbol: "ambient" }, { Variable: 0 }]
            },
            {
                name: "operation",
                ids: [{ Symbol: "ambient" }, { Symbol: "read" }]
            },
            {
                name: "right",
                ids: [{ Symbol: "authority" }, { Variable: 0 }, { Symbol: "read" }]
            }
        ]
    )

    blockBuilder.add_caveat(rules)
    let block2 = blockBuilder.build()

    let keypair2 = wasm.keypair_new()
    let biscuit2 = biscuit1.append(keypair2, block2)
    assert.ok(biscuit2 !== null && biscuit2 !== undefined)
};
