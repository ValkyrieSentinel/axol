fn main() {
    println!("cargo:rerun-if-changed=src/scanner.s");
    cc::Build::new()
        .file("src/scanner.s")
        .compile("scanner_asm");
}