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
                Slice s;
                s.ptr = (const uint8_t *) seed;
                s.len = strlen(seed);

                KeyPair * root_kp = keypair_new(s);
                printf("keypair creation error? %s\n", error_message());
                PublicKey* root = keypair_public(root_kp);

                BiscuitBuilder* b = biscuit_builder(root_kp);
                printf("builder creation error? %s\n", error_message());
                biscuit_builder_add_authority_fact(b, "right(#authority, \"file1\", #read)");

                printf("builder add authority error? %s\n", error_message());

                Biscuit * biscuit = biscuit_builder_build(b, s);
                printf("Hello, World!\n");
                printf("biscuit creation error? %s\n", error_message());

                Verifier * verifier = biscuit_verify(biscuit, root);
                printf("verifier creation error? %s\n", error_message());
                verifier_add_caveat(verifier, "*right(#abcd) <- right(#efgh)");
                printf("verifier add caveat error? %s\n", error_message());
                char* world_print = verifier_print(verifier);
                printf("verifier world:\n%s\n", world_print);
                string_free(world_print);
                if(!verifier_verify(verifier)) {
                    printf("verifier error: %s\n", error_message());
                } else {
                    printf("verifier succeeded\n");
                }

                verifier_free(verifier);
                biscuit_free(biscuit);
                public_key_free(root);
                keypair_free(root_kp);

                return 0;
            }
        })
        .success()
        .stdout("Hello world");
    }
}
