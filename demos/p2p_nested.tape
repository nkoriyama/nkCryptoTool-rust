# Nested / chained bastion-less PQC P2P: shell into host A, run `nkct
# --serve-scp` inside that shell, then fetch A's file from outside.
# Render:  vhs demos/p2p_nested.tape
Output docs/p2p_nested_demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1340
Set Height 560
Set Padding 14
Set TypingSpeed 45ms

Hide
Type "cd '/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust' && clear"
Enter
Show

Type "# Nested PQC P2P: shell into A -> run 'nkct --serve-scp' inside A -> fetch A's file"
Enter
Sleep 1200ms
Type "bash demos/p2p_nested_demo.sh"
Enter
Sleep 28s
