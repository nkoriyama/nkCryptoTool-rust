# Bastion-less PQC P2P file transfer (scp) — Linux <-> Linux, loopback iroh.
# Runs the self-pacing demos/p2p_scp_demo.sh.
# Render:  vhs demos/p2p_scp.tape
Output docs/demos/p2p_scp_demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1320
Set Height 600
Set Padding 14
Set TypingSpeed 45ms

Hide
Type "cd '/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust' && clear"
Enter
Show

Type "# Bastion-less PQC P2P file transfer (scp)  —  1 GiB transfer with a live progress bar"
Enter
Sleep 1200ms
Type "bash demos/p2p_scp_demo.sh"
Enter
Sleep 34s
