# Bastion-less PQC P2P pairing (ssh-copy-id equivalent) and what it unlocks:
# an unregistered client self-registers over a one-time token on nkct/pairing/1,
# then the same ML-DSA-65 fingerprint drives a command-confined shell and a
# path-jailed scp — loopback iroh, default-deny preserved. Runs the self-pacing
# demos/pairing_demo.sh.
# Render:  vhs demos/pairing.tape
Output docs/pairing_demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1360
Set Height 720
Set Padding 16
Set TypingSpeed 45ms

Hide
Type "cd '/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust' && clear"
Enter
Show

Type "# ssh-copy-id for bastion-less PQC P2P: pair once -> confined shell + scp (iroh, ML-DSA-65)"
Enter
Sleep 1200ms
Type "bash demos/pairing_demo.sh"
Enter
Sleep 29s
