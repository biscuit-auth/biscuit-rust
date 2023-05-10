# Biscuit samples and expected results

root secret key: 12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a
root public key: acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189

------------------------------

## basic token: test001_basic.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

authorizer code:
```
resource("file1");

allow if true;
```

revocation ids:
- `36d2d7cf28796c69a0ed6dfa0fde5b3ffb2f637f0ba19aa1da858353e88678ad945ebaaa566a050b8abe8adb5b873855900b157e1e5f1cc11047a14385e5a203`
- `b694af382e2115df7d02bb88a75b9c0cdcb9e51c23dea082c306b1b7a26dfe9a3ca7ba7ca3a8089e7b88bb3718ff0294c2a0dc6b5b810f64462e89393ff35e05`

authorizer world:
```
World {
  facts: {
    (
        "resource(\"file1\")",
        {
            None,
        },
    ),
    (
        "right(\"file1\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "right(\"file1\", \"write\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "right(\"file2\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if resource($0), operation(\"read\"), right($0, \"read\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($0), operation(\"read\"), right($0, \"read\")" })] }))`


------------------------------

## different root key: test002_different_root_key.bc
### token

authority:
symbols: ["file1"]

public keys: []

```
right("file1", "read");
```

1:
symbols: ["0"]

public keys: []

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## invalid signature format: test003_invalid_signature_format.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(InvalidSignatureSize(16)))`


------------------------------

## random block: test004_random_block.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## invalid signature: test005_invalid_signature.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## reordered blocks: test006_reordered_blocks.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

```
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: []

public keys: []

```
check if resource("file1");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## scoped rules: test007_scoped_rules.bc
### token

authority:
symbols: ["user_id", "alice", "file1"]

public keys: []

```
user_id("alice");
owner("alice", "file1");
```

1:
symbols: ["0", "1"]

public keys: []

```
right($0, "read") <- resource($0), user_id($1), owner($1, $0);
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: ["file2"]

public keys: []

```
owner("alice", "file2");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

allow if true;
```

revocation ids:
- `9ff0d3b8dcd5235b5d88e17a21d5c789953e3bf4769ee40f34d4bc276b8672858504f6ae8098c43328a1e60589d7efc0e5fd2ec70a229904a1c493262d498c09`
- `9e82a5f203e17d0515af7486599c1608d82a41c8e8cfe4457cb30c0eb62273d89970a2316223ccfdb64a49214762e80e82938531a2e0dc462f14ff52205e9107`
- `c24b1da5ece026338fd3175648e443b97dce52659efe47881583cd35574670b21abdb345ebd0adf095620d8d7b805028fdcb480c24170d34e023e3a8df29fb04`

authorizer world:
```
World {
  facts: {
    (
        "operation(\"read\")",
        {
            None,
        },
    ),
    (
        "owner(\"alice\", \"file1\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "owner(\"alice\", \"file2\")",
        {
            Some(
                2,
            ),
        },
    ),
    (
        "resource(\"file2\")",
        {
            None,
        },
    ),
    (
        "user_id(\"alice\")",
        {
            Some(
                0,
            ),
        },
    ),
}
  rules: {
    (
        "right($0, \"read\") <- resource($0), user_id($1), owner($1, $0)",
        Some(
            1,
        ),
    ),
}
  checks: {
    "check if resource($0), operation(\"read\"), right($0, \"read\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($0), operation(\"read\"), right($0, \"read\")" })] }))`


------------------------------

## scoped checks: test008_scoped_checks.bc
### token

authority:
symbols: ["file1"]

public keys: []

```
right("file1", "read");
```

1:
symbols: ["0"]

public keys: []

```
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: ["file2"]

public keys: []

```
right("file2", "read");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

allow if true;
```

revocation ids:
- `ba4d8f66dd4e3fef1f35d75be6df25fc41fbe237f645ea4434678add9dc356be23462eb1ada51bbb446995539f43b5d04581190ce2de66ea6194563efe88d603`
- `3a69659a56d933ea7bf2dc4ccab997ed0bec6ce26b178ec24a9ec0d2fc006bcf31eae762f17cb5862457459b3d5ae9c17845dcf45f8cf0acd774e06f6b7d620d`
- `c0f06ebdf58b5e17b150e7306a9361667a6a6d9945c1d478b4e8d9fac1869bd7726ef57e5cb9de95fe48718984e7dce617d5394caf25822cd646310affb2a202`

authorizer world:
```
World {
  facts: {
    (
        "operation(\"read\")",
        {
            None,
        },
    ),
    (
        "resource(\"file2\")",
        {
            None,
        },
    ),
    (
        "right(\"file1\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "right(\"file2\", \"read\")",
        {
            Some(
                2,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if resource($0), operation(\"read\"), right($0, \"read\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($0), operation(\"read\"), right($0, \"read\")" })] }))`


------------------------------

## expired token: test009_expired_token.bc
### token

authority:
symbols: []

public keys: []

```
```

1:
symbols: ["file1", "expiration"]

public keys: []

```
check if resource("file1");
check if time($time), $time <= 2018-12-20T00:00:00Z;
```

### validation

authorizer code:
```
resource("file1");
operation("read");
time(2020-12-21T09:23:12Z);

allow if true;
```

revocation ids:
- `ceb1a909c91d558a962c23d9d1c60aa06279f9dff1cc546ca6b2b6bf17db6fe4a03a04e9c1ed9131b7c6f3e609d5f17abab289909ae46f5e66f8876a5946a20c`
- `73e270352f08a98007b383ac85192f878a098c7ae55bbd1b7da67a44d9e94a5192aa02277707ec6747ec973aa0d7e270cd73bb0b46df2d8e434e4b9a06571208`

authorizer world:
```
World {
  facts: {
    (
        "operation(\"read\")",
        {
            None,
        },
    ),
    (
        "resource(\"file1\")",
        {
            None,
        },
    ),
    (
        "time(2020-12-21T09:23:12Z)",
        {
            None,
        },
    ),
}
  rules: {}
  checks: {
    "check if resource(\"file1\")",
    "check if time($time), $time <= 2018-12-20T00:00:00Z",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 1, rule: "check if time($time), $time <= 2018-12-20T00:00:00Z" })] }))`


------------------------------

## authorizer scope: test010_authorizer_scope.bc
### token

authority:
symbols: ["file1"]

public keys: []

```
right("file1", "read");
```

1:
symbols: ["file2"]

public keys: []

```
right("file2", "read");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

check if right($0, $1), resource($0), operation($1);

allow if true;
```

revocation ids:
- `ba4d8f66dd4e3fef1f35d75be6df25fc41fbe237f645ea4434678add9dc356be23462eb1ada51bbb446995539f43b5d04581190ce2de66ea6194563efe88d603`
- `d1d56ea3c9469186fe32f56a2c488b31b2dead6701ce833d521d2b1f223355edb058839c68ea6b50af02e2ffa4b92d80116b25f1cb0623b6685cb3415677970a`

authorizer world:
```
World {
  facts: {
    (
        "operation(\"read\")",
        {
            None,
        },
    ),
    (
        "resource(\"file2\")",
        {
            None,
        },
    ),
    (
        "right(\"file1\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "right(\"file2\", \"read\")",
        {
            Some(
                1,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if right($0, $1), resource($0), operation($1)",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Authorizer(FailedAuthorizerCheck { check_id: 0, rule: "check if right($0, $1), resource($0), operation($1)" })] }))`


------------------------------

## authorizer authority checks: test011_authorizer_authority_caveats.bc
### token

authority:
symbols: ["file1"]

public keys: []

```
right("file1", "read");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

check if right($0, $1), resource($0), operation($1);

allow if true;
```

revocation ids:
- `ba4d8f66dd4e3fef1f35d75be6df25fc41fbe237f645ea4434678add9dc356be23462eb1ada51bbb446995539f43b5d04581190ce2de66ea6194563efe88d603`

authorizer world:
```
World {
  facts: {
    (
        "operation(\"read\")",
        {
            None,
        },
    ),
    (
        "resource(\"file2\")",
        {
            None,
        },
    ),
    (
        "right(\"file1\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if right($0, $1), resource($0), operation($1)",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Authorizer(FailedAuthorizerCheck { check_id: 0, rule: "check if right($0, $1), resource($0), operation($1)" })] }))`


------------------------------

## authority checks: test012_authority_caveats.bc
### token

authority:
symbols: ["file1"]

public keys: []

```
check if resource("file1");
```

### validation for "file1"

authorizer code:
```
resource("file1");
operation("read");

allow if true;
```

revocation ids:
- `bc15caa9476568fef796c13385d0cf455df66a0b1aa2be7980549f69aa5a4a7864555d94ddd64c652c7c24c191298dd5c0ca1aadb638ffd91971d15edee0aa07`

authorizer world:
```
World {
  facts: {
    (
        "operation(\"read\")",
        {
            None,
        },
    ),
    (
        "resource(\"file1\")",
        {
            None,
        },
    ),
}
  rules: {}
  checks: {
    "check if resource(\"file1\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`
### validation for "file2"

authorizer code:
```
resource("file2");
operation("read");

allow if true;
```

revocation ids:
- `bc15caa9476568fef796c13385d0cf455df66a0b1aa2be7980549f69aa5a4a7864555d94ddd64c652c7c24c191298dd5c0ca1aadb638ffd91971d15edee0aa07`

authorizer world:
```
World {
  facts: {
    (
        "operation(\"read\")",
        {
            None,
        },
    ),
    (
        "resource(\"file2\")",
        {
            None,
        },
    ),
}
  rules: {}
  checks: {
    "check if resource(\"file1\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource(\"file1\")" })] }))`


------------------------------

## block rules: test013_block_rules.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

```
right("file1", "read");
right("file2", "read");
```

1:
symbols: ["valid_date", "0", "1"]

public keys: []

```
valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59Z;
valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, !["file1"].contains($1);
check if valid_date($0), resource($0);
```

### validation for "file1"

authorizer code:
```
resource("file1");
time(2020-12-21T09:23:12Z);

allow if true;
```

revocation ids:
- `58a9aead6684468383ba121d1d1ba6a2dd087f41240ecb3b8229587b7717630d5db86e230c4aa3a6da802f04483da06ae4cb71c7c35f30207550be4450787601`
- `745941a089e3e4efc479ac8d934fc0f95d9add8dca119c68e2ef34dfb285385396ad9b2d2cf6633894c234b1b9c854978be6788ca05262e3d2362e82f984b605`

authorizer world:
```
World {
  facts: {
    (
        "resource(\"file1\")",
        {
            None,
        },
    ),
    (
        "right(\"file1\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "right(\"file2\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "time(2020-12-21T09:23:12Z)",
        {
            None,
        },
    ),
    (
        "valid_date(\"file1\")",
        {
            None,
            Some(
                1,
            ),
        },
    ),
}
  rules: {
    (
        "valid_date(\"file1\") <- time($0), resource(\"file1\"), $0 <= 2030-12-31T12:59:59Z",
        Some(
            1,
        ),
    ),
    (
        "valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, ![\"file1\"].contains($1)",
        Some(
            1,
        ),
    ),
}
  checks: {
    "check if valid_date($0), resource($0)",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`
### validation for "file2"

authorizer code:
```
resource("file2");
time(2020-12-21T09:23:12Z);

allow if true;
```

revocation ids:
- `58a9aead6684468383ba121d1d1ba6a2dd087f41240ecb3b8229587b7717630d5db86e230c4aa3a6da802f04483da06ae4cb71c7c35f30207550be4450787601`
- `745941a089e3e4efc479ac8d934fc0f95d9add8dca119c68e2ef34dfb285385396ad9b2d2cf6633894c234b1b9c854978be6788ca05262e3d2362e82f984b605`

authorizer world:
```
World {
  facts: {
    (
        "resource(\"file2\")",
        {
            None,
        },
    ),
    (
        "right(\"file1\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "right(\"file2\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "time(2020-12-21T09:23:12Z)",
        {
            None,
        },
    ),
}
  rules: {
    (
        "valid_date(\"file1\") <- time($0), resource(\"file1\"), $0 <= 2030-12-31T12:59:59Z",
        Some(
            1,
        ),
    ),
    (
        "valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, ![\"file1\"].contains($1)",
        Some(
            1,
        ),
    ),
}
  checks: {
    "check if valid_date($0), resource($0)",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if valid_date($0), resource($0)" })] }))`


------------------------------

## regex_constraint: test014_regex_constraint.bc
### token

authority:
symbols: ["0", "file[0-9]+.txt"]

public keys: []

```
check if resource($0), $0.matches("file[0-9]+.txt");
```

### validation for "file1"

authorizer code:
```
resource("file1");

allow if true;
```

revocation ids:
- `7d2e7c6bc4878efcdb7f704948e668fcf5338cb1e4eeb5f0434944ace98597652f062d67e2ebdb47fe2c7b17d40f0d8a2386cb2d753fb430168be5e0b5fd410b`

authorizer world:
```
World {
  facts: {
    (
        "resource(\"file1\")",
        {
            None,
        },
    ),
}
  rules: {}
  checks: {
    "check if resource($0), $0.matches(\"file[0-9]+.txt\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource($0), $0.matches(\"file[0-9]+.txt\")" })] }))`
### validation for "file123"

authorizer code:
```
resource("file123.txt");

allow if true;
```

revocation ids:
- `7d2e7c6bc4878efcdb7f704948e668fcf5338cb1e4eeb5f0434944ace98597652f062d67e2ebdb47fe2c7b17d40f0d8a2386cb2d753fb430168be5e0b5fd410b`

authorizer world:
```
World {
  facts: {
    (
        "resource(\"file123.txt\")",
        {
            None,
        },
    ),
}
  rules: {}
  checks: {
    "check if resource($0), $0.matches(\"file[0-9]+.txt\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## multi queries checks: test015_multi_queries_caveats.bc
### token

authority:
symbols: ["must_be_present", "hello"]

public keys: []

```
must_be_present("hello");
```

### validation

authorizer code:
```
check if must_be_present($0) or must_be_present($0);

allow if true;
```

revocation ids:
- `e2c762315434ccc9194e012e47e75afb3329a46488a468d75d776b5a502ee5930d04750ae7b1836617fe07051bd92d4ce8336d662da4ca9ce9e9d4f4af5be70d`

authorizer world:
```
World {
  facts: {
    (
        "must_be_present(\"hello\")",
        {
            Some(
                0,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if must_be_present($0) or must_be_present($0)",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## check head name should be independent from fact names: test016_caveat_head_name.bc
### token

authority:
symbols: ["hello"]

public keys: []

```
check if resource("hello");
```

1:
symbols: ["test"]

public keys: []

```
query("test");
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `812958ef3b43273b2c8e88bb13d0f91f0a8f5bf95544f79dafdaff07d89bd551baca72f83589b9e89120b0dc41c0f4b10678f03dd1b3ac0422e16074ff396b08`
- `51c0e278bed1085afe45519aa60d5b4b9e13f1819dadb38fb5854ed3a599bfe18485d8f396219540bd17bfb9f46ab3c407a4ac51ebf88734b4f2fb56b24a6e01`

authorizer world:
```
World {
  facts: {
    (
        "query(\"test\")",
        {
            Some(
                1,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if resource(\"hello\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource(\"hello\")" })] }))`


------------------------------

## test expression syntax and all available operations: test017_expressions.bc
### token

authority:
symbols: ["hello world", "hello", "world", "aaabde", "a*c?.e", "abd", "aaa", "b", "de", "abcD12", "abc", "def"]

public keys: []

```
check if true;
check if !false;
check if !false && true;
check if false || true;
check if (true || false) && true;
check if true == true;
check if false == false;
check if 1 < 2;
check if 2 > 1;
check if 1 <= 2;
check if 1 <= 1;
check if 2 >= 1;
check if 2 >= 2;
check if 3 == 3;
check if 1 + 2 * 3 - 4 / 2 == 5;
check if "hello world".starts_with("hello") && "hello world".ends_with("world");
check if "aaabde".matches("a*c?.e");
check if "aaabde".contains("abd");
check if "aaabde" == "aaa" + "b" + "de";
check if "abcD12" == "abcD12";
check if 2019-12-04T09:46:41Z < 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z > 2019-12-04T09:46:41Z;
check if 2019-12-04T09:46:41Z <= 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z >= 2019-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z == 2020-12-04T09:46:41Z;
check if hex:12ab == hex:12ab;
check if [1, 2].contains(2);
check if [2019-12-04T09:46:41Z, 2020-12-04T09:46:41Z].contains(2020-12-04T09:46:41Z);
check if [false, true].contains(true);
check if ["abc", "def"].contains("abc");
check if [hex:12ab, hex:34de].contains(hex:34de);
check if [1, 2].contains([2]);
check if [1, 2] == [1, 2];
check if [1, 2].intersection([2, 3]) == [2];
check if [1, 2].union([2, 3]) == [1, 2, 3];
check if [1, 2, 3].intersection([1, 2]).contains(1);
check if [1, 2, 3].intersection([1, 2]).length() == 2;
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `a0fdd27c0d21292a4d944a86a9e97cfee7513969a209729ebcff2dec50b8725816dad3b9d7fc004d3f6dc705399c303c1a76a8b955a5f23d2045132b68b4d50b`

authorizer world:
```
World {
  facts: {}
  rules: {}
  checks: {
    "check if !false",
    "check if !false && true",
    "check if \"aaabde\" == \"aaa\" + \"b\" + \"de\"",
    "check if \"aaabde\".contains(\"abd\")",
    "check if \"aaabde\".matches(\"a*c?.e\")",
    "check if \"abcD12\" == \"abcD12\"",
    "check if \"hello world\".starts_with(\"hello\") && \"hello world\".ends_with(\"world\")",
    "check if (true || false) && true",
    "check if 1 + 2 * 3 - 4 / 2 == 5",
    "check if 1 < 2",
    "check if 1 <= 1",
    "check if 1 <= 2",
    "check if 2 > 1",
    "check if 2 >= 1",
    "check if 2 >= 2",
    "check if 2019-12-04T09:46:41Z < 2020-12-04T09:46:41Z",
    "check if 2019-12-04T09:46:41Z <= 2020-12-04T09:46:41Z",
    "check if 2020-12-04T09:46:41Z == 2020-12-04T09:46:41Z",
    "check if 2020-12-04T09:46:41Z > 2019-12-04T09:46:41Z",
    "check if 2020-12-04T09:46:41Z >= 2019-12-04T09:46:41Z",
    "check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z",
    "check if 3 == 3",
    "check if [\"abc\", \"def\"].contains(\"abc\")",
    "check if [1, 2, 3].intersection([1, 2]).contains(1)",
    "check if [1, 2, 3].intersection([1, 2]).length() == 2",
    "check if [1, 2] == [1, 2]",
    "check if [1, 2].contains(2)",
    "check if [1, 2].contains([2])",
    "check if [1, 2].intersection([2, 3]) == [2]",
    "check if [1, 2].union([2, 3]) == [1, 2, 3]",
    "check if [2019-12-04T09:46:41Z, 2020-12-04T09:46:41Z].contains(2020-12-04T09:46:41Z)",
    "check if [false, true].contains(true)",
    "check if [hex:12ab, hex:34de].contains(hex:34de)",
    "check if false == false",
    "check if false || true",
    "check if hex:12ab == hex:12ab",
    "check if true",
    "check if true == true",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## invalid block rule with unbound_variables: test018_unbound_variables_in_rule.bc
### token

authority:
symbols: []

public keys: []

```
check if operation("read");
```

1:
symbols: ["unbound", "any1", "any2"]

public keys: []

```
operation($unbound, "read") <- operation($any1, $any2);
```

### validation

result: `Err(FailedLogic(InvalidBlockRule(0, "operation($unbound, \"read\") <- operation($any1, $any2)")))`


------------------------------

## invalid block rule generating an #authority or #ambient symbol with a variable: test019_generating_ambient_from_variables.bc
### token

authority:
symbols: []

public keys: []

```
check if operation("read");
```

1:
symbols: ["any"]

public keys: []

```
operation("read") <- operation($any);
```

### validation

authorizer code:
```
operation("write");

allow if true;
```

revocation ids:
- `6d79797e655457166810826d7c398bc75ac4896d8de80650298796faf0aaf67f2abb80c46efdd915a210c9401bc41c75f3a7c19bebe4c02be9c991fae62b8808`
- `f7d3f3eadd83cc30aa3c0a9b8288d44b9107b5a099e52da6447fdb7aca5d00cd58add7b7b12b3fb73bd9b664f33ed207d91efcda2d05523cb9b8db0e9bca0502`

authorizer world:
```
World {
  facts: {
    (
        "operation(\"read\")",
        {
            None,
            Some(
                1,
            ),
        },
    ),
    (
        "operation(\"write\")",
        {
            None,
        },
    ),
}
  rules: {
    (
        "operation(\"read\") <- operation($any)",
        Some(
            1,
        ),
    ),
}
  checks: {
    "check if operation(\"read\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if operation(\"read\")" })] }))`


------------------------------

## sealed token: test020_sealed.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

authorizer code:
```
resource("file1");
operation("read");

allow if true;
```

revocation ids:
- `36d2d7cf28796c69a0ed6dfa0fde5b3ffb2f637f0ba19aa1da858353e88678ad945ebaaa566a050b8abe8adb5b873855900b157e1e5f1cc11047a14385e5a203`
- `b694af382e2115df7d02bb88a75b9c0cdcb9e51c23dea082c306b1b7a26dfe9a3ca7ba7ca3a8089e7b88bb3718ff0294c2a0dc6b5b810f64462e89393ff35e05`

authorizer world:
```
World {
  facts: {
    (
        "operation(\"read\")",
        {
            None,
        },
    ),
    (
        "resource(\"file1\")",
        {
            None,
        },
    ),
    (
        "right(\"file1\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "right(\"file1\", \"write\")",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "right(\"file2\", \"read\")",
        {
            Some(
                0,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if resource($0), operation(\"read\"), right($0, \"read\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## parsing: test021_parsing.bc
### token

authority:
symbols: ["ns::fact_123", "hello é\t😁"]

public keys: []

```
ns::fact_123("hello é	😁");
```

### validation

authorizer code:
```
check if ns::fact_123("hello é	😁");

allow if true;
```

revocation ids:
- `6a945aca807c25971cc4b711cd6364141fdaf4cee013022416f22986240238cc029b5ae41eb5c5b8a461b0d6063329132b5bac91ca8b51e82829a2b6a273150d`

authorizer world:
```
World {
  facts: {
    (
        "ns::fact_123(\"hello é\t😁\")",
        {
            Some(
                0,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if ns::fact_123(\"hello é\t😁\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## default_symbols: test022_default_symbols.bc
### token

authority:
symbols: []

public keys: []

```
read(0);
write(1);
resource(2);
operation(3);
right(4);
time(5);
role(6);
owner(7);
tenant(8);
namespace(9);
user(10);
team(11);
service(12);
admin(13);
email(14);
group(15);
member(16);
ip_address(17);
client(18);
client_ip(19);
domain(20);
path(21);
version(22);
cluster(23);
node(24);
hostname(25);
nonce(26);
query(27);
```

### validation

authorizer code:
```
check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27);

allow if true;
```

revocation ids:
- `23183284bdad88fbf5b4cbaed2218cf0a38d7e360f3ac401d6337eecf36e8da1ce15eda6d11fe94c20c344f687327d9338a0e863f98c9a14576739533d2fb804`

authorizer world:
```
World {
  facts: {
    (
        "admin(13)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "client(18)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "client_ip(19)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "cluster(23)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "domain(20)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "email(14)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "group(15)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "hostname(25)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "ip_address(17)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "member(16)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "namespace(9)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "node(24)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "nonce(26)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "operation(3)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "owner(7)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "path(21)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "query(27)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "read(0)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "resource(2)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "right(4)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "role(6)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "service(12)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "team(11)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "tenant(8)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "time(5)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "user(10)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "version(22)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "write(1)",
        {
            Some(
                0,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27)",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## execution scope: test023_execution_scope.bc
### token

authority:
symbols: ["authority_fact"]

public keys: []

```
authority_fact(1);
```

1:
symbols: ["block1_fact"]

public keys: []

```
block1_fact(1);
```

2:
symbols: ["var"]

public keys: []

```
check if authority_fact($var);
check if block1_fact($var);
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `8c94b6f3a2cbe086a7df1135f04c7b88b4a8d6b4f595cd963e8f2a36b9c1edb551f1b0360f7995eec8ea8c846847fba53932f5e70aaee7783a852c83c08dd80b`
- `ce286369809e4f4a6e2d6b95ba6c19af28c3694ffd408d09ee292c0233a3d73e3257151d6099177ae61aa71cfb91f85b3ccac80952bf5d34c9e807c5e4cf2c04`
- `9bc1209ffa1e11d5fd3fe3811e55893e6c5a94d56e5835e83f7a84142db50642899b92705a32ab64a375e36e665564607cbf50d6366682b5381849f8e8b3340a`

authorizer world:
```
World {
  facts: {
    (
        "authority_fact(1)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "block1_fact(1)",
        {
            Some(
                1,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if authority_fact($var)",
    "check if block1_fact($var)",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 2, check_id: 1, rule: "check if block1_fact($var)" })] }))`


------------------------------

## third party: test024_third_party.bc
### token

authority:
symbols: []

public keys: ["ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"]

```
right("read");
check if group("admin") trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

1:
symbols: []

public keys: []

external signature by: "ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

```
group("admin");
check if right("read");
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `f5e36f36c18a9a7d3660366a9dccf1eeefbb2a639571e5aba63714cf02e412d222f7aadec14aef59cb5cf104e0d3bdba439c4147249e2d703498b2f0610e1008`
- `79217fcc94823ccbfc1cdbd6aaf770890659bb94d48ca14dddff70e9d0d386a4755e452e732a071c8e9884ca280ead059c473b3bd4ea5f82e99ee3c484518004`

authorizer world:
```
World {
  facts: {
    (
        "group(\"admin\")",
        {
            Some(
                1,
            ),
        },
    ),
    (
        "right(\"read\")",
        {
            Some(
                0,
            ),
        },
    ),
}
  rules: {}
  checks: {
    "check if group(\"admin\") trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
    "check if right(\"read\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## block rules: test025_check_all.bc
### token

authority:
symbols: ["allowed_operations", "A", "B", "op", "allowed"]

public keys: []

```
allowed_operations(["A", "B"]);
check all operation($op), allowed_operations($allowed), $allowed.contains($op);
```

### validation for "A, B"

authorizer code:
```
operation("A");
operation("B");

allow if true;
```

revocation ids:
- `96f15d9598d682d387d9f01b4df28f6f29e6e2a0d2cdd699266a685e983f64c8349054a77ca7e940d6775da79ed53d41373863e3a35b86181d132148a8d5980a`

authorizer world:
```
World {
  facts: {
    (
        "allowed_operations([\"A\", \"B\"])",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "operation(\"A\")",
        {
            None,
        },
    ),
    (
        "operation(\"B\")",
        {
            None,
        },
    ),
}
  rules: {}
  checks: {
    "check all operation($op), allowed_operations($allowed), $allowed.contains($op)",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`
### validation for "A, invalid"

authorizer code:
```
operation("A");
operation("invalid");

allow if true;
```

revocation ids:
- `96f15d9598d682d387d9f01b4df28f6f29e6e2a0d2cdd699266a685e983f64c8349054a77ca7e940d6775da79ed53d41373863e3a35b86181d132148a8d5980a`

authorizer world:
```
World {
  facts: {
    (
        "allowed_operations([\"A\", \"B\"])",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "operation(\"A\")",
        {
            None,
        },
    ),
    (
        "operation(\"invalid\")",
        {
            None,
        },
    ),
}
  rules: {}
  checks: {
    "check all operation($op), allowed_operations($allowed), $allowed.contains($op)",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check all operation($op), allowed_operations($allowed), $allowed.contains($op)" })] }))`


------------------------------

## public keys interning: test026_public_keys_interning.bc
### token

authority:
symbols: []

public keys: ["ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"]

```
query(0);
check if true trusting previous, ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

1:
symbols: []

public keys: ["ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463"]

external signature by: "ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

```
query(1);
query(1, 2) <- query(1), query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

2:
symbols: []

public keys: []

external signature by: "ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463"

```
query(2);
check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

3:
symbols: []

public keys: []

external signature by: "ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463"

```
query(3);
check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

4:
symbols: []

public keys: ["ed25519/f98da8c1cf907856431bfc3dc87531e0eaadba90f919edc232405b85877ef136"]

```
query(4);
check if query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(4) trusting ed25519/f98da8c1cf907856431bfc3dc87531e0eaadba90f919edc232405b85877ef136;
```

### validation

authorizer code:
```
check if query(1, 2) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189, ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;

deny if query(3);
deny if query(1, 2);
deny if query(0) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
allow if true;
```

revocation ids:
- `0e823acf10d97afef5d327d08ecde17fad1808388dedf678770b60521170180f4ad3b4dc81494d92122658f3bbfe2567ad5493b2bf0fc6570f2be52566320d03`
- `35bacaf3a817a26ffcb6a2b5658ef60665b63696c00061f5cef75fe3dac315595f0e24c20533916d90077b708e62396bf4b50dcd774092b43100f9271cd9830a`
- `3198c7f606e1611e6a6df503b74a9ac5769dd11b3a1c6c4d5f0e3dbf92671d009e0ec648fadc49442e9c94455258c8502ed2d5031a57436f2521520a0b9ac009`
- `16f8e0231f514816282621730510e41e0ba1a41d1944634f13fe4aaf28d0565e658fa624186fafc0bd996af39b638a31904b637e24ecc791f3d7210f9b83d90e`
- `68db0a0319dd91ee6638fe5fe380f9037c63b37fd0674b9df01cae5e40fcfe37a04498cba34a92433c6f9d3c423be5a5fbee49136b734f9d98d1b7962c1e730b`

authorizer world:
```
World {
  facts: {
    (
        "query(0)",
        {
            Some(
                0,
            ),
        },
    ),
    (
        "query(1)",
        {
            Some(
                1,
            ),
        },
    ),
    (
        "query(1, 2)",
        {
            Some(
                1,
            ),
            Some(
                2,
            ),
        },
    ),
    (
        "query(2)",
        {
            Some(
                2,
            ),
        },
    ),
    (
        "query(3)",
        {
            Some(
                3,
            ),
        },
    ),
    (
        "query(4)",
        {
            Some(
                4,
            ),
        },
    ),
}
  rules: {
    (
        "query(1, 2) <- query(1), query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
        Some(
            1,
        ),
    ),
}
  checks: {
    "check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
    "check if query(1, 2) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189, ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
    "check if query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
    "check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
    "check if query(4) trusting ed25519/f98da8c1cf907856431bfc3dc87531e0eaadba90f919edc232405b85877ef136",
    "check if true trusting previous, ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
}
  policies: {
    "allow if true",
    "deny if query(0) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
    "deny if query(1, 2)",
    "deny if query(3)",
}
}
```

result: `Ok(3)`


------------------------------

## integer wraparound: test027_integer_wraparound.bc
### token

authority:
symbols: []

public keys: []

```
check if true || 10000000000 * 10000000000 != 0;
check if true || 9223372036854775807 + 1 != 0;
check if true || -9223372036854775808 - 1 != 0;
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `c554195c11cd462ca550f833833fad64213bdbef31d5e4b48ae6c2dc072d5218792bbf0da612f7ec9d20dc04c505d8c6ebdeee96ae95307546227efca713c70b`

authorizer world:
```
World {
  facts: {}
  rules: {}
  checks: {
    "check if true || -9223372036854775808 - 1 != 0",
    "check if true || 10000000000 * 10000000000 != 0",
    "check if true || 9223372036854775807 + 1 != 0",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(Execution(Overflow))`


------------------------------

## test expression syntax and all available operations (v4 blocks): test028_expressions_v4.bc
### token

authority:
symbols: ["abcD12x", "abcD12"]

public keys: []

```
check if 1 != 3;
check if 1 | 2 ^ 3 == 0;
check if "abcD12x" != "abcD12";
check if 2022-12-04T09:46:41Z != 2020-12-04T09:46:41Z;
check if hex:12abcd != hex:12ab;
check if [1, 4] != [1, 2];
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `56ff3e571202e641dfb84955adb6700b61e42e1100412b3e0e957f1693875fbb8fdeaeb008092b2f42c5c7ded97cde638eeaf3ab73df678273f6ba970916ad00`

authorizer world:
```
World {
  facts: {}
  rules: {}
  checks: {
    "check if \"abcD12x\" != \"abcD12\"",
    "check if 1 != 3",
    "check if 1 | 2 ^ 3 == 0",
    "check if 2022-12-04T09:46:41Z != 2020-12-04T09:46:41Z",
    "check if [1, 4] != [1, 2]",
    "check if hex:12abcd != hex:12ab",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`

