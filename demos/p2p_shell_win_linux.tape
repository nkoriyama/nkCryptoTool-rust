# Bastion-less PQC P2P shell — Linux (client) -> Windows (server, ConPTY).
# Real hole-punch over the LAN to a live Windows box. Render while the Windows
# server is running (ticket in /var/home/bazzite/win_ticket2.txt).
# Render:  vhs demos/p2p_shell_win_linux.tape
Output docs/p2p_shell_win_linux_demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1300
Set Height 720
Set Padding 14
Set TypingSpeed 55ms

Hide
Type "cd '/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust' && unset RUST_LOG && clear"
Enter
Show

Type "# Bastion-less PQC P2P shell   Linux (client)  -->  Windows (server / ConPTY)"
Enter
Sleep 900ms
Type "# mutual ML-DSA-65 auth, direct LAN hole-punch, no open inbound port"
Enter
Sleep 1200ms

Type './target/release/nk-crypto-tool --shell --tui --connect "$(cat /var/home/bazzite/win_ticket2.txt)" --mode pqc --signing-privkey ~/nkct-test/keys/private_sign_pqc.key --signing-pubkey /var/mnt/data/nkct-windows-pub.key'
Enter
Sleep 5s

Type "whoami"
Enter
Sleep 1600ms
Type "ver"
Enter
Sleep 1600ms
Type "hostname"
Enter
Sleep 1600ms
Type "echo reached a Windows shell bastion-less over PQC P2P"
Enter
Sleep 2200ms
Type "exit"
Enter
Sleep 3000ms
