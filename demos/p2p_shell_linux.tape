# Bastion-less PQC P2P shell — Linux <-> Linux (loopback iroh).
# Render:  vhs demos/p2p_shell_linux.tape
Output docs/demos/p2p_shell_linux_demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1240
Set Height 660
Set Padding 14
Set TypingSpeed 55ms

Hide
Type "cd '/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust' && clear"
Enter
Show

Type "# Bastion-less PQC P2P shell  —  Linux <-> Linux  (ML-KEM-768 + ML-DSA-65)"
Enter
Sleep 900ms
Type "source demos/p2p_shell_demo.sh   # keygen + start server + grab ticket"
Enter
Sleep 3s

Type 'nkct --shell --tui --connect "$TICKET" --mode pqc --signing-privkey "$CKEY" --signing-pubkey "$SPUB"'
Enter
Sleep 4s

Type "whoami"
Enter
Sleep 1200ms
Type "hostname"
Enter
Sleep 1200ms
Type "uname -srm"
Enter
Sleep 1200ms
Type "echo 'reached the server bastion-less — no open port, mutual PQC auth'"
Enter
Sleep 1800ms
Ctrl+D
Sleep 2500ms

Type "grep -a 'authenticated' demos/.state/server.log   # server-side audit"
Enter
Sleep 2800ms
