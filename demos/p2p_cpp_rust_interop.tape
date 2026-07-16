# C++ <-> Rust nkCryptoTool P2P interop: scp, shell (both ways), pairing (both ways).
# Runs the self-pacing demos/p2p_cpp_rust_interop.sh (needs ../nkCryptoTool/build-both).
# Render:  vhs demos/p2p_cpp_rust_interop.tape
Output docs/demos/p2p_cpp_rust_interop_demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1400
Set Height 760
Set Padding 14
Set TypingSpeed 45ms

Hide
Type "cd '/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust' && clear"
Enter
Show

Type "# Every bastion-less P2P role, C++ <-> Rust, both directions"
Enter
Sleep 1200ms
Type "bash demos/p2p_cpp_rust_interop.sh"
Enter
Sleep 34s
