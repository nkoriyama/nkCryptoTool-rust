fn main() {
    // slint-build's `compile()` sets the `SLINT_INCLUDE_GENERATED`
    // env var to its output path. A second `compile()` would
    // overwrite it, losing the first compile's modules. So we route
    // through a single entry-point `.slint` per feature combination:
    // bare `gui` uses `chat.slint`, while `gui-mls` uses
    // `_entry_gui_mls.slint` (which re-exports both the chat window
    // and the MLS group window in one document).
    #[cfg(all(feature = "gui", not(feature = "gui-mls")))]
    slint_build::compile("src/gui/chat.slint").expect("Slint build (chat.slint) failed");

    #[cfg(feature = "gui-mls")]
    slint_build::compile("src/gui/_entry_gui_mls.slint")
        .expect("Slint build (_entry_gui_mls.slint) failed");

    // `shell_desktop`: the interactive PTY shell (server + client) is supported
    // only on desktop OSes — unix excluding mobile (android/ios), plus windows.
    // Other targets compile an error stub and never pull `portable-pty`. This
    // must match the `portable-pty` target predicate in Cargo.toml.
    println!("cargo::rustc-check-cfg=cfg(shell_desktop)");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let is_mobile = target_os == "android" || target_os == "ios";
    let families: Vec<&str> = target_family.split(',').collect();
    let is_desktop =
        (families.contains(&"unix") && !is_mobile) || families.contains(&"windows");
    if is_desktop {
        println!("cargo::rustc-cfg=shell_desktop");
    }
}
