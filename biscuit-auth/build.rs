fn main() {
    println!("cargo:rerun-if-changed=src/format/schema.proto");
    //prost_build::compile_protos(&["src/format/schema.proto"], &["src/"]).unwrap();
}
