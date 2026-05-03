fn main() {
    let version = std::env::var("AXIOMVAULT_VERSION")
        .unwrap_or_else(|_| std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION set"));

    println!("cargo:rustc-env=AXIOMVAULT_VERSION={version}");
    println!("cargo:rerun-if-env-changed=AXIOMVAULT_VERSION");
}
