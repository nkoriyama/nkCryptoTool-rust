# The full keyring workflow on one loopback host: an unregistered client copies
# its KeyBundle to the server (ssh-copy-id), the server then encrypts a file TO
# that client by handle (bundle pulled from the keyring), the client fetches the
# ciphertext over nkct/scp/1, and only the client can decrypt it. One ML-DSA-65
# identity, no open port. Runs the self-pacing demos/copy_encrypt_scp_demo.sh.
# Render:  vhs demos/copy_encrypt_scp.tape
Output docs/demos/copy_encrypt_scp_demo.gif

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

Type "# keyring workflow: copy-bundle -> encrypt-to-handle -> scp -> decrypt (iroh, ML-DSA-65)"
Enter
Sleep 1200ms
Type "bash demos/copy_encrypt_scp_demo.sh"
Enter
Sleep 24s
