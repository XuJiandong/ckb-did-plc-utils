use std::process::Command;

fn compile(schema: &str) {
    let out_dir = std::path::PathBuf::from("./src/molecules");
    std::fs::create_dir_all(&out_dir).unwrap();

    let mut compiler = molecule_codegen::Compiler::new();
    compiler
        .input_schema_file(schema)
        .generate_code(molecule_codegen::Language::RustLazyReader)
        .output_dir(out_dir)
        .run()
        .unwrap();
}

fn main() {
    println!("cargo:rerun-if-changed=molecules/cell_data.mol");
    println!("cargo:rerun-if-changed=molecules/witness.mol");
    compile("molecules/cell_data.mol");
    compile("molecules/witness.mol");

    let output = Command::new("cargo")
        .arg("fmt")
        .arg("--")
        .arg("src/molecules/cell_data.rs")
        .arg("src/molecules/witness.rs")
        .output()
        .expect("Failed to execute command");

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        panic!("Command failed: {}", error);
    }
}
