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
                biscuit_builder_add_authority_fact(b, "right(#authority, \"file1\", #read)");

                printf("builder add authority error? %s\n", error_message());

                Biscuit * biscuit = biscuit_builder_build(b, (const uint8_t * ) seed, strlen(seed));
                printf("biscuit creation error? %s\n", error_message());

                BlockBuilder* bb = biscuit_create_block(biscuit);
                printf("block builder creation error? %s\n", error_message());
                block_builder_add_caveat(bb, "*op(#read) <- operation(#ambient, #read)");
                block_builder_add_fact(bb, "hello(\"world\")");
                printf("builder add caveat error? %s\n", error_message());

                char *seed2 = "ijklmnopijklmnopijklmnopijklmnop";
                char *seed3 = "ABCDEFGHABCDEFGHABCDEFGHABCDEFGH";

                KeyPair * kp2 = key_pair_new((const uint8_t *) seed2, strlen(seed2));

                Biscuit* b2 = biscuit_append_block(biscuit, bb, kp2, (const uint8_t*) seed3, strlen(seed3));
                printf("biscuit append error? %s\n", error_message());

                Verifier * verifier = biscuit_verify(b2, root);
                printf("verifier creation error? %s\n", error_message());
                verifier_add_caveat(verifier, "*right(#abcd) <- right(#efgh)");
                printf("verifier add caveat error? %s\n", error_message());
                char* world_print = verifier_print(verifier);
                printf("verifier world:\n%s\n", world_print);
                string_free(world_print);
                if(!verifier_verify(verifier)) {
                    printf("verifier error(code = %d): %s\n", error_kind(), error_message());

                    if(error_kind() == LogicFailedCaveats) {
                        uint64_t error_count = error_caveat_count();
                        printf("failed caveats (%ld):\n", error_count);

                        for(uint64_t i = 0; i < error_count; i++) {
                            if(error_caveat_is_verifier(i)) {
                                uint64_t caveat_id = error_caveat_id(i);
                                const char* rule = error_caveat_rule(i);

                                printf("  Verifier caveat %ld: %s\n", caveat_id, rule);
                            } else {
                                uint64_t caveat_id = error_caveat_id(i);
                                uint64_t block_id = error_caveat_block_id(i);
                                const char* rule = error_caveat_rule(i);
                                printf("  Block %ld, caveat %ld: %s\n", block_id, caveat_id, rule);
                            }

                        }
                    }
                } else {
                    printf("verifier succeeded\n");
                }

                uint64_t sz = biscuit_serialized_size(b2);
                printf("serialized size: %ld\n", sz);
                uint8_t * buffer = malloc(sz);
                uint64_t written = biscuit_serialize(b2, buffer);
                printf("wrote %ld bytes\n", written);

                free(buffer);
                verifier_free(verifier);
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
        .stdout(r#"key_pair creation error? (null)
builder creation error? (null)
builder add authority error? (null)
biscuit creation error? (null)
block builder creation error? (null)
builder add caveat error? (null)
biscuit append error? (null)
verifier creation error? (null)
verifier add caveat error? (null)
verifier world:
World {
  facts: [
    "hello(\"world\")",
    "right(#authority, \"file1\", #read)",
]
  rules: []
  caveats: [
    "Verifier[0]: *right(#abcd) <- right(#efgh)",
    "Block[1][0]: *op(#read) <- operation(#ambient, #read)",
]
}
verifier error(code = 20): caveat validation failed
failed caveats (2):
  Verifier caveat 0: *right(#abcd) <- right(#efgh)
  Block 1, caveat 0: *op(#read) <- operation(#ambient, #read)
serialized size: 273
wrote 273 bytes
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
