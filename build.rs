fn main() {
    #[cfg(feature = "gui")]
    slint_build::compile("src/gui/chat.slint").expect("Slint build failed");
}
