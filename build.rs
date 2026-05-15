fn main() {
    let version = std::env::var("AXIOM_VERSION")
        .or_else(|_| std::env::var("AXIOMVAULT_VERSION"))
        .unwrap_or_else(|_| std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION set"));

    println!("cargo:rustc-env=AXIOM_VERSION={version}");
    println!("cargo:rustc-env=AXIOMVAULT_VERSION={version}");
    println!("cargo:rerun-if-env-changed=AXIOM_VERSION");
    println!("cargo:rerun-if-env-changed=AXIOMVAULT_VERSION");
}
