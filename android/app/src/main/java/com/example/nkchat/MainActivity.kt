package com.example.nkchat

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import uniffi.nk_crypto_tool.MobileChatClient
import uniffi.nk_crypto_tool.libraryVersion

/**
 * Minimal smoke-test UI for the Rust MLS chat core (libnk_crypto_tool.so via
 * UniFFI). Tapping the button opens a [MobileChatClient] against the app's
 * private storage, creates an MLS group, and shows the result.
 *
 * The heavy lifting (hybrid PQC MLS, redb storage, iroh P2P) all happens in the
 * Rust .so; this Activity is only a thin driver. See ../../README.md.
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val log = TextView(this)
        val createBtn = Button(this).apply { text = "Create MLS group" }
        val ticketBtn = Button(this).apply { text = "Show my ticket" }

        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(32, 48, 32, 32)
                addView(TextView(this@MainActivity).apply {
                    text = "nkCryptoTool MLS — core v${libraryVersion()}"
                })
                addView(createBtn)
                addView(ticketBtn)
                addView(log)
            }
        )

        createBtn.setOnClickListener {
            lifecycleScope.launch {
                runCatching {
                    // disable_relay = false → use public relays (needs INTERNET).
                    val client = MobileChatClient.open(
                        filesDir.absolutePath, "demo-pass", "android-user", false,
                    )
                    client.use {
                        val gid = it.createGroup()
                        val groups = it.listGroups()
                        "created group:\n$gid\n\nall groups: ${groups.joinToString()}"
                    }
                }.onSuccess { log.text = it }
                    .onFailure { log.text = "error: ${it.message}" }
            }
        }

        ticketBtn.setOnClickListener {
            lifecycleScope.launch {
                runCatching {
                    MobileChatClient.open(
                        filesDir.absolutePath, "demo-pass", "android-user", false,
                    ).use { it.localTicket() }
                }.onSuccess { log.text = "my ticket (share with a peer):\n$it" }
                    .onFailure { log.text = "error: ${it.message}" }
            }
        }
    }
}
