use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let ndpi_dir = manifest_dir.join("vendor/nDPI");
    let ndpi_include_dir = ndpi_dir.join("src/include");
    let ndpi_lib_dir = ndpi_dir.join("src/lib");

    ensure_ndpi_sources_present(&ndpi_dir, &ndpi_include_dir, &ndpi_lib_dir);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let generated_include_dir = out_dir.join("include");
    fs::create_dir_all(&generated_include_dir)
        .expect("failed to create generated include directory");

    println!("cargo:rerun-if-changed=build.rs");
    let ndpi_define_template = ndpi_include_dir.join("ndpi_define.h.in");

    println!("cargo:rerun-if-changed={}", ndpi_define_template.display());

    copy_public_headers(&ndpi_include_dir, &generated_include_dir);
    write_ndpi_config_header(&generated_include_dir);
    write_ndpi_define_header(&ndpi_define_template, &generated_include_dir);

    let c_sources = collect_c_sources(&ndpi_lib_dir);

    let mut build = cc::Build::new();
    // nDPI is vendored third-party C code. Keep the Cargo build quiet unless
    // there is an actual compile failure.
    build.warnings(false);
    build.files(&c_sources);
    build.include(&generated_include_dir);
    build.include(&ndpi_include_dir);
    build.include(&ndpi_lib_dir);
    build.include(ndpi_lib_dir.join("third_party/include"));
    build.define("NDPI_LIB_COMPILATION", None);
    // Allow detection modules to share LRU caches through a global context,
    // as nDPI's configure does by default. This adds a pthread mutex to the
    // public struct ndpi_lru_cache, which the bindings keep opaque.
    build.define("USE_GLOBAL_CONTEXT", None);
    build.define("_DEFAULT_SOURCE", Some("1"));
    build.define("_GNU_SOURCE", Some("1"));
    build.flag_if_supported("-std=gnu11");
    build.flag_if_supported("-fPIC");
    build.flag_if_supported("-Wno-unused-function");
    build.flag_if_supported("-Wno-unused-parameter");
    build.flag_if_supported("-Wno-attributes");
    build.flag_if_supported("-Wno-discarded-qualifiers");
    build.flag_if_supported("-Wno-maybe-uninitialized");
    build.compile("ndpi");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        println!("cargo:rustc-link-lib=m");
    }

    println!("cargo:include={}", generated_include_dir.display());
}

fn ensure_ndpi_sources_present(ndpi_dir: &Path, ndpi_include_dir: &Path, ndpi_lib_dir: &Path) {
    if ndpi_include_dir.is_dir() && ndpi_lib_dir.is_dir() {
        return;
    }

    panic!(
        "nDPI source tree not found at '{}'. This repository expects vendored nDPI sources.",
        ndpi_dir.display()
    );
}

fn copy_public_headers(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).expect("failed to read nDPI include directory") {
        let entry = entry.expect("failed to read include directory entry");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("h") {
            let file_name = path.file_name().expect("header without file name");
            fs::copy(&path, destination.join(file_name))
                .expect("failed to copy nDPI public header");
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

const NDPI_MAJOR: &str = "6";
const NDPI_MINOR: &str = "0";
const NDPI_PATCH: &str = "0";
const NDPI_VERSION: &str = "6.0.0";

fn write_ndpi_config_header(generated_include_dir: &Path) {
    let header = format!(
        "#pragma once\n\n\
         #define NDPI_MAJOR_RELEASE \"{}\"\n\
         #define NDPI_MINOR_RELEASE \"{}\"\n\
         #define NDPI_PATCH_LEVEL \"{}\"\n\
         #define NDPI_GIT_RELEASE \"{}\"\n\
         #define NDPI_GIT_DATE \"unknown\"\n",
        NDPI_MAJOR, NDPI_MINOR, NDPI_PATCH, NDPI_VERSION
    );

    fs::write(generated_include_dir.join("ndpi_config.h"), header)
        .expect("failed to write ndpi_config.h");
}

/// Render `ndpi_define.h` from the upstream autoconf template, substituting
/// the values configure would otherwise provide.
fn write_ndpi_define_header(ndpi_define_template: &Path, generated_include_dir: &Path) {
    let template =
        fs::read_to_string(ndpi_define_template).expect("failed to read nDPI ndpi_define.h.in");

    let rendered = template
        .replace("@NDPI_API_VERSION@", "0")
        .replace("@NDPI_MAJOR@", NDPI_MAJOR)
        .replace("@NDPI_MINOR@", NDPI_MINOR)
        .replace("@NDPI_PATCH@", NDPI_PATCH);

    if let Some(line) = rendered.lines().find(|line| has_autoconf_token(line)) {
        panic!(
            "unhandled autoconf substitution in ndpi_define.h.in: {}",
            line
        );
    }

    fs::write(generated_include_dir.join("ndpi_define.h"), rendered)
        .expect("failed to write ndpi_define.h");
}

/// Returns true if the line contains an `@NAME@` autoconf substitution token.
fn has_autoconf_token(line: &str) -> bool {
    line.split('@').skip(1).step_by(2).any(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    }) && line.matches('@').count() >= 2
}

fn collect_c_sources(ndpi_lib_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    files.extend(collect_c_sources_from_dir(ndpi_lib_dir));
    files.extend(collect_c_sources_from_dir(&ndpi_lib_dir.join("protocols")));
    files.extend(collect_c_sources_from_dir(
        &ndpi_lib_dir.join("third_party/src"),
    ));
    files.extend(collect_c_sources_from_dir(
        &ndpi_lib_dir.join("third_party/src/hll"),
    ));

    files.sort();

    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }

    files
}

fn collect_c_sources_from_dir(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = WalkDir::new(dir)
        .max_depth(1)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("c"))
        .collect();

    files.sort();
    files
}
