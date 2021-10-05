//#[cfg(test)]
#[cfg(feature = "capi")]
mod capi {
    use inline_c::assert_c;

    #[test]
    fn build() {
        (assert_c! {
            #include <stdio.h>
            #include <string.h>
            #include "biscuit_auth.h"

            int main() {
                char *seed = "abcdefghabcdefghabcdefghabcdefgh";

                KeyPair * root_kp = key_pair_new((const uint8_t *) seed, strlen(seed));
                printf("key_pair creation error? %s\n", error_message());
                PublicKey* root = key_pair_public(root_kp);

                BiscuitBuilder* b = biscuit_builder(root_kp);
                printf("builder creation error? %s\n", error_message());
                biscuit_builder_add_authority_fact(b, "right(\"file1\", \"read\")");

                printf("builder add authority error? %s\n", error_message());

                Biscuit * biscuit = biscuit_builder_build(b, (const uint8_t * ) seed, strlen(seed));
                printf("biscuit creation error? %s\n", error_message());

                BlockBuilder* bb = biscuit_create_block(biscuit);
                printf("block builder creation error? %s\n", error_message());
                block_builder_add_check(bb, "check if operation(\"read\")");
                block_builder_add_fact(bb, "hello(\"world\")");
                printf("builder add check error? %s\n", error_message());

                char *seed2 = "ijklmnopijklmnopijklmnopijklmnop";

                KeyPair * kp2 = key_pair_new((const uint8_t *) seed2, strlen(seed2));

                Biscuit* b2 = biscuit_append_block(biscuit, bb, kp2);
                printf("biscuit append error? %s\n", error_message());

                Authorizer * authorizer = biscuit_authorizer(b2);
                printf("authorizer creation error? %s\n", error_message());
                authorizer_add_check(authorizer, "check if right(\"efgh\")");
                printf("authorizer add check error? %s\n", error_message());
                if(!authorizer_authorize(authorizer)) {
                    printf("authorizer error(code = %d): %s\n", error_kind(), error_message());

                    if(error_kind() == LogicFailedChecks) {
                        uint64_t error_count = error_check_count();
                        printf("failed checks (%ld):\n", error_count);

                        for(uint64_t i = 0; i < error_count; i++) {
                            if(error_check_is_authorizer(i)) {
                                uint64_t check_id = error_check_id(i);
                                const char* rule = error_check_rule(i);

                                printf("  Authorizer check %ld: %s\n", check_id, rule);
                            } else {
                                uint64_t check_id = error_check_id(i);
                                uint64_t block_id = error_check_block_id(i);
                                const char* rule = error_check_rule(i);
                                printf("  Block %ld, check %ld: %s\n", block_id, check_id, rule);
                            }

                        }
                    }
                } else {
                    printf("authorizer succeeded\n");
                }
                char* world_print = authorizer_print(authorizer);
                printf("authorizer world:\n%s\n", world_print);
                string_free(world_print);

                uint64_t sz = biscuit_serialized_size(b2);
                printf("serialized size: %ld\n", sz);
                uint8_t * buffer = malloc(sz);
                uint64_t written = biscuit_serialize(b2, buffer);
                printf("wrote %ld bytes\n", written);

                free(buffer);
                authorizer_free(authorizer);
                block_builder_free(bb);
                biscuit_free(b2);
                key_pair_free(kp2);
                biscuit_free(biscuit);
                public_key_free(root);
                key_pair_free(root_kp);

                return 0;
            }
        })
        .success()
        .stdout(
            r#"key_pair creation error? (null)
builder creation error? (null)
builder add authority error? (null)
biscuit creation error? (null)
block builder creation error? (null)
builder add check error? (null)
biscuit append error? (null)
authorizer creation error? (null)
authorizer add check error? (null)
authorizer error(code = 22): check validation failed
failed checks (2):
  Authorizer check 0: check if right("efgh")
  Block 1, check 0: check if operation("read")
authorizer world:
World {
  facts: [
    "hello(\"world\")",
    "revocation_id(0, hex:399f4cd638039d645f317b6401ef8308e56d4e4d983538386070e5cbb368198e63fded9e0a55e1e22e3c92f49e3e3de46f74c2fac45fb75bc546270be15ed80b)",
    "revocation_id(1, hex:dbd504ed972e732df9d6f29103bea2dc6dbe2c86e47bdaeb13e3947c9136b33827f4c4bb24c6fbfd2c4b69acc8f5aaaaeb44e911406e892bcc8d76555629ba0e)",
    "right(\"file1\", \"read\")",
]
  rules: []
  checks: [
    "Authorizer[0]: check if right(\"efgh\")",
]
  policies: []
}
serialized size: 332
wrote 332 bytes
"#);
    }

    #[test]
    fn serialize_keys() {
        (assert_c! {
            #include <stdio.h>
            #include <string.h>
            #include "biscuit_auth.h"

            int main() {
                char *seed = "abcdefghabcdefghabcdefghabcdefgh";
                uint8_t * priv_buf = malloc(32);
                uint8_t * pub_buf = malloc(32);


                KeyPair * kp = key_pair_new((const uint8_t *) seed, strlen(seed));
                printf("key_pair creation error? %s\n", error_message());
                PublicKey* pubkey = key_pair_public(kp);

                key_pair_serialize(kp, priv_buf);
                public_key_serialize(pubkey, pub_buf);

                public_key_free(pubkey);
                key_pair_free(kp);
            }
        })
        .success()
        .stdout("key_pair creation error? (null)\n");
    }
}
