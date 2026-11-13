fn main() {
    // Rootless jailbreaks install under /var/jb; rootful ones (every iOS 14 jailbreak) use /.
    let prefix = std::env::var("SLIPSTREAM_PREFIX").unwrap_or_else(|_| "/var/jb".into());
    println!("cargo:rustc-env=SLIPSTREAM_PREFIX={prefix}");
    println!("cargo:rerun-if-env-changed=SLIPSTREAM_PREFIX");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("ios") {
        return;
    }
    cc::Build::new()
        .file("src/app_catalog.m")
        .file("src/tunnel.m")
        .define("SLIPSTREAM_PREFIX", format!("\"{prefix}\"").as_str())
        .flag("-fobjc-arc")
        .flag("-fblocks")
        .flag("-Wno-deprecated-declarations")
        .compile("slipstream_native");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Network");
    println!("cargo:rustc-link-lib=framework=NetworkExtension");
    println!("cargo:rerun-if-changed=src/app_catalog.m");
    println!("cargo:rerun-if-changed=src/tunnel.m");
    println!("cargo:rerun-if-changed=provider/ProviderInterface.h");
}
