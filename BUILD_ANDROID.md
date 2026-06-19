# Android クロスコンパイル手順（aarch64-linux-android）

`mls` ストレージを SQLCipher から純 Rust の redb へ移行した結果（`DB_PURERUST_DESIGN.md`）、
`mls` ビルドは **system libcrypto / SQLCipher に依存しなくなり、Android へクロスコンパイル可能**
になった。本書は実機ターゲットで検証済みの手順を記録する。

## 検証結果（2026-06-18, NDK r27c）

```
$ cargo ndk -t arm64-v8a build --no-default-features --features "backend-rustcrypto mls"
   Finished `dev` profile

$ file target/aarch64-linux-android/debug/nk-crypto-tool
ELF 64-bit LSB pie executable, ARM aarch64, interpreter /system/bin/linker64

$ llvm-readelf -d <bin> | grep NEEDED
  libdl.so   libm.so   libc.so       # Bionic コアのみ
  # libcrypto / libssl / libsqlite は無し
```

`ring`（rustls→iroh 経由の暗号）は NDK の clang で **静的リンク**されバイナリに同梱される
（system 依存にはならない）。

## 前提

- Bazzite 等の immutable ホストでは **distrobox** 内で作業するのが楽。`rustup`/`cargo` は
  `$HOME/.cargo` 共有なのでホスト/コンテナどちらの rustup でもよい。
- NDK は **r26 以降**（検証は r27c）。

## セットアップ（distrobox 例: Ubuntu コンテナ）

```bash
# 非対話でも可: distrobox enter <name> -- bash -lc '...'
rustup target add aarch64-linux-android
cargo install cargo-ndk

# NDK 取得（~600MB）。/tmp が tmpfs の環境では実ディスク上に展開すること。
curl -fL -o ~/android-ndk-r27c-linux.zip \
  https://dl.google.com/android/repository/android-ndk-r27c-linux.zip
unzip -q ~/android-ndk-r27c-linux.zip -d ~/
```

## ビルド

```bash
export ANDROID_NDK_HOME=~/android-ndk-r27c
cargo ndk -t arm64-v8a build --release \
  --no-default-features --features "backend-rustcrypto mls"
# 生成物: target/aarch64-linux-android/release/ 以下
```

他 ABI は `-t armeabi-v7a -t x86_64` 等を追加。`cargo-ndk` が NDK の clang を
リンカに設定する（手動なら `.cargo/config.toml` の
`[target.aarch64-linux-android] linker = "<ndk>/.../aarch64-linux-android<API>-clang"`）。

## アプリ組み込み（cdylib / JNI）

`Cargo.toml` の `[lib] crate-type = ["rlib", "cdylib"]` により、上記ビルドは
実行ファイルに加えて **`libnk_crypto_tool.so`（C-ABI 共有ライブラリ）**も生成する。

検証済み（aarch64, NDK r27c）:
```
$ file target/aarch64-linux-android/debug/libnk_crypto_tool.so
ELF 64-bit LSB shared object, ARM aarch64
$ llvm-readelf -d <so> | grep NEEDED
  libdl.so   libc.so          # libcrypto/libssl/libsqlite は無し
```

この `.so` を Android アプリ（Kotlin/Java）から `System.loadLibrary("nk_crypto_tool")` で
ロードできる。なお iroh の P2P ネットワークは実機/エミュレータでの動作確認が別途必要。

### UniFFI ブリッジ（`mobile-ffi` feature）

`src/ffi.rs` に `#[uniffi::export]` でエクスポート面を定義し、`mobile-ffi` feature で
cdylib に組み込む。Kotlin バインディングは同梱の `uniffi-bindgen` bin で生成する:

```sh
# cdylib をビルド（android なら上記 cargo ndk に mobile-ffi を足す）
cargo build --no-default-features --features "backend-rustcrypto mls mobile-ffi"

# 生成（--library モードで cdylib のメタデータから生成）
cargo run --no-default-features --features "backend-rustcrypto mls mobile-ffi" \
  --bin uniffi-bindgen -- generate \
  --library target/debug/libnk_crypto_tool.so --language kotlin --out-dir bindings/kotlin
# → bindings/kotlin/uniffi/nk_crypto_tool/nk_crypto_tool.kt
# （ktlint があれば自動整形。無くても生成は成功する）
```

現状のエクスポート:
- 関数: `libraryVersion()`, `hybridSuiteId()`, `sha3256Fingerprint(data)`
- **`MobileChatClient`（UniFFI object, async, `suspend fun` + `AutoCloseable`）**:
  `open(storageDir, passphrase, displayName, disableRelay)` でストレージ(redb)＋iroh
  エンドポイント＋`GroupChatProcessor` を構築。
  - ローカル: `createGroup()`, `listGroups()`, `localTicket()`, `exportKeyPackage()`
  - 招待: `inviteMember(gidHex, keyPackage)→welcome`, `sendWelcome(ticket, welcome)`,
    `joinGroup(welcome)→gidHex`
  - メッセージ: `sendText(gidHex, text, recipientTickets)`,
    `receiveNext()→FfiChatEvent`（NewGroup/Message/EpochAdvanced/RemovedFromGroup）

E2E 検証メモ: 単ノードのローカル操作（group 作成・ticket・KeyPackage）は headless テスト済み。
ピア間の招待/送受信は **2ノード（実機/エミュレータ or 2プロセス）必要**で、その疎通確認が残課題。

`bindings/` は生成物なのでコミットしない（`.gitignore` 済み、上記コマンドで再生成）。

## 注意

- **`legacy-sqlcipher-migration` feature を付けてはいけない**（rusqlite/SQLCipher を引き戻し、
  Android では system libcrypto が無くリンクできない）。これは旧 DB 移行ツール専用で、
  デスクトップでのみ使う。
- 旧 SQLCipher DB を持つユーザは、デスクトップで一度
  `nk-crypto-tool --mls-cmd migrate-from-sqlcipher` を実行して redb 形式へ移行してから
  モバイルへ持ち込む（`migrate.rs`）。
