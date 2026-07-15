# Bastion-less PQC P2P shell — the Windows .exe under Wine, as a client to a
# Linux host. Runs the self-pacing demos/p2p_wine_demo.sh inside the winbuild
# distrobox (where wine64 lives).
# Render:  vhs demos/p2p_wine.tape
Output docs/demos/p2p_wine_demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1300
Set Height 620
Set Padding 14
Set TypingSpeed 45ms

Hide
Type "cd '/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust' && clear"
Enter
Show

Type "# nkct Windows .exe under Wine  -->  bastion-less PQC P2P to a Linux host"
Enter
Sleep 1200ms
Type "distrobox enter winbuild -- bash demos/p2p_wine_demo.sh"
Enter
Sleep 30s
