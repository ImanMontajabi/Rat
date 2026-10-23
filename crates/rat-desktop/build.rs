fn main() {
    // GPUI's composed native views need more headroom than Windows' default
    // 1 MiB main-thread stack, particularly in unoptimized development builds.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg-bin=rat-desktop=/STACK:8388608");
        println!("cargo:rerun-if-changed=resources/rat.rc");
        println!("cargo:rerun-if-changed=resources/rat.ico");
        embed_resource::compile_for("resources/rat.rc", ["rat-desktop"], embed_resource::NONE)
            .manifest_required()
            .expect("Cannot embed Rat's Windows icon");
    }
}
