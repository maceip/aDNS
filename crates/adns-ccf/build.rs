fn main() {
    println!("cargo:rerun-if-env-changed=CCF_INCLUDE_DIR");
    #[cfg(feature = "ccf")]
    {
        let include = std::env::var("CCF_INCLUDE_DIR")
            .expect("CCF_INCLUDE_DIR must identify the pinned CCF 7.0.15 SDK include directory");
        cxx_build::bridge("src/bridge.rs")
            .file("src/ccf_tx.cpp")
            .include("include")
            .include(&include)
            .include(format!("{include}/3rdparty"))
            .std("c++23")
            .flag_if_supported("-Wno-unused-parameter")
            .compile("adns_ccf_tx");
        println!("cargo:rerun-if-changed=src/bridge.rs");
        println!("cargo:rerun-if-changed=src/ccf_tx.cpp");
        println!("cargo:rerun-if-changed=include/adns-ccf/ccf_tx.h");
    }
}
