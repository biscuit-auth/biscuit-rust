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

                BiscuitBuilder* b = biscuit_builder();
                printf("builder creation error? %s\n", error_message());
                biscuit_builder_add_fact(b, "right(\"file1\", \"read\")");

                printf("builder add authority error? %s\n", error_message());

                Biscuit * biscuit = biscuit_builder_build(b, root_kp, (const uint8_t * ) seed, strlen(seed));
                printf("biscuit creation error? %s\n", error_message());

                BlockBuilder* bb = create_block();
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

                authorizer_add_policy(authorizer, "allow if true");
                printf("authorizer add policy error? %s\n", error_message());

                if(!authorizer_authorize(authorizer)) {
                    printf("authorizer error(code = %d): %s\n", error_kind(), error_message());

                    if(error_kind() == LogicUnauthorized) {
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
builder add check error? (null)
biscuit append error? (null)
authorizer creation error? (null)
authorizer add check error? (null)
authorizer add policy error? (null)
authorizer error(code = 16): authorization failed
failed checks (2):
  Authorizer check 0: check if right("efgh")
  Block 1, check 0: check if operation("read")
authorizer world:
World {
  facts: [
    "right(\"file1\", \"read\")",
]
  rules: []
  checks: [
    "Authorizer[0]: check if right(\"efgh\")",
]
  policies: [
    "allow if true",
]
}
serialized size: 322
wrote 322 bytes
"#,
        );
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
