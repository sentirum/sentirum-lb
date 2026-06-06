fn main() {
    println!("cargo:rerun-if-changed=proto/echo.proto");

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to resolve protoc");
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/echo.proto"], &["proto"])
        .expect("failed to compile test proto");
}
