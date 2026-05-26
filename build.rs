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
}
