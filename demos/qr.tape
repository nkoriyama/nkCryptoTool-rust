# Render a connection ticket as a terminal QR — no external qrencode, no network.
# Runs the self-pacing demos/qr_demo.sh.
# Render:  vhs demos/qr.tape
Output docs/demos/qr_demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 880
Set Height 800
Set Padding 14
Set TypingSpeed 45ms

Hide
Type "cd '/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust' && clear"
Enter
Show

Type "# Show a connection ticket as a QR, right in the terminal"
Enter
Sleep 1200ms
Type "bash demos/qr_demo.sh"
Enter
Sleep 16s
