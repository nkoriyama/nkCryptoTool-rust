# Asynchronous bastion-less PQC delivery: signed recipient bundle + One-Time
# Prekey inbox (PQ forward secret) — loopback iroh, sender & recipient never
# online together. Runs the self-pacing demos/p2p_bundle_demo.sh.
# Render:  vhs demos/p2p_bundle.tape
Output docs/p2p_bundle_demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1320
Set Height 640
Set Padding 14
Set TypingSpeed 45ms

Hide
Type "cd '/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust' && clear"
Enter
Show

Type "# Async PQC delivery via a signed recipient bundle + One-Time Prekey inbox (PQ-FS)"
Enter
Sleep 1200ms
Type "bash demos/p2p_bundle_demo.sh"
Enter
Sleep 24s
