# F-IROH-40: rustcrypto backend でビルド不可

作成日: 2026-05-07
更新日: 2026-05-07 (実環境情報追加)
分類: **Critical (Ubuntu LTS 利用ブロッカー + mobile 展開ブロッカー)**
発見経緯: 2026-05-07 ユーザが nkwire (Ubuntu 24.04 LTS / OpenSSL 3.0.13) 上で `cargo test --release --no-default-features --features backend-rustcrypto` 実行時に発見

---

## 症状

`backend-rustcrypto` feature でビルドすると **コンパイルエラー 3 件**:

```
error[E0599]: no method named `get_public_key` found for struct `fips203::types::DecapsKey<DK_LEN>` in the current scope
   --> src/backend/rustcrypto_impl.rs:631:23
    |
631 |                 Ok(sk.get_public_key().into_bytes().to_vec())
    |                       ^^^^^^^^^^^^^^ method not found in `fips203::types::DecapsKey<1632>`

error[E0599]: no method named `get_public_key` found for struct `fips203::types::DecapsKey<DK_LEN>` in the current scope
   --> src/backend/rustcrypto_impl.rs:636:23
    |
636 |                 Ok(sk.get_public_key().into_bytes().to_vec())
    |                       ^^^^^^^^^^^^^^ method not found in `fips203::types::DecapsKey<2400>`

error[E0599]: no method named `get_public_key` found for struct `fips203::types::DecapsKey<DK_LEN>` in the current scope
   --> src/backend/rustcrypto_impl.rs:641:23
    |
641 |                 Ok(sk.get_public_key().into_bytes().to_vec())
    |                       ^^^^^^^^^^^^^^ method not found in `fips203::types::DecapsKey<3168>`

error: could not compile `nk-crypto-tool` (lib) due to 3 previous errors; 3 warnings emitted
error: could not compile `nk-crypto-tool` (lib test) due to 3 previous errors; 5 warnings emitted
```

3 箇所とも ML-KEM の各サイズ (512 / 768 / 1024) の `DecapsKey` に対して `get_public_key()` を呼んでいる箇所。

## 再現コマンド

```bash
CARGO_TARGET_DIR=target_rustcrypto \
  cargo test --release --no-default-features --features backend-rustcrypto
```

build / test どちらも同じエラーで失敗。

## 根本原因

`fips203` crate の **API 変更**。

`Cargo.toml:16` で `fips203 = "0.4"` と固定されているが、`0.4` 系内でも minor patch で `DecapsKey::get_public_key()` メソッドが廃止 / リネームされた可能性が高い。

該当コード `src/backend/rustcrypto_impl.rs:625-645` 周辺:

```rust
pub fn pqc_pub_from_priv_kem(algo: &str, priv_key: &[u8]) -> Result<Vec<u8>> {
    match algo {
        "ML-KEM-512" => {
            let sk = ml_kem_512::DecapsKey::try_from_bytes(priv_key.try_into()?)?;
            Ok(sk.get_public_key().into_bytes().to_vec())   // ← line 631
        }
        "ML-KEM-768" => {
            let sk = ml_kem_768::DecapsKey::try_from_bytes(priv_key.try_into()?)?;
            Ok(sk.get_public_key().into_bytes().to_vec())   // ← line 636
        }
        "ML-KEM-1024" => {
            let sk = ml_kem_1024::DecapsKey::try_from_bytes(priv_key.try_into()?)?;
            Ok(sk.get_public_key().into_bytes().to_vec())   // ← line 641
        }
        _ => Err(...),
    }
}
```

この関数は **Phase 3 (V3.1 ハンドシェイク) で新規追加** されたもので、サーバ側で ML-KEM 公開鍵を秘密鍵から再導出してクライアントに送信するために使われる (F-IROH-26 修正で導入)。

つまり Phase 3 完了時点で **openssl backend のみで動作確認 / テスト** され、rustcrypto backend では **一度もビルドが通っていない**。

## 影響範囲

| 項目 | 状態 |
|---|---|
| openssl backend での chat / ファイル転送 (OpenSSL 3.5+) | ✅ 動作 |
| openssl backend (OpenSSL 3.2-3.4 + oqs-provider) | △ プラグイン要 |
| **openssl backend (OpenSSL 3.0-3.1)** | ❌ **PQC 未対応で実行時失敗** |
| rustcrypto backend での chat / ファイル転送 | ❌ **ビルド不可 (本件)** |
| openssl backend のテスト | ✅ 17/17 PASS |
| rustcrypto backend のテスト | ❌ **コンパイル失敗** |
| static binary / Alpine / Docker scratch 等 | ❌ rustcrypto 必要なため不可 |
| iOS / Android クロスコンパイル | ❌ 同上 |
| **chat GUI (Slint) mobile 展開** | ❌ **致命的ブロッカー** |

### Linux ディストリビューション別の影響

OpenSSL の標準パッケージバージョンと PQC サポート状況:

| ディストリ | 標準 OpenSSL | PQC 対応 | F-IROH-40 影響 |
|---|---|---|---|
| **Ubuntu 24.04 LTS** (2024-04 〜 2034-04) | **3.0.13** | ❌ | 🔴 **rustcrypto 必須だが本件で不可** |
| Ubuntu 22.04 LTS (〜 2032-04) | 3.0.2 | ❌ | 🔴 同上 |
| Debian 12 (bookworm) | 3.0.x | ❌ | 🔴 同上 |
| Debian 13 (trixie, 2025-) | 3.4+ | △ (oqs-provider 経由) | 🟡 設定要 |
| RHEL 9 / Rocky 9 / Alma 9 | 3.0 / 3.2 | ❌ / △ | 🔴 / 🟡 |
| Fedora 40+ | 3.2+ | △ | 🟡 |
| Arch Linux (rolling) | 3.5+ | ✅ | ✅ |
| openSUSE Tumbleweed | 3.5+ | ✅ | ✅ |
| **Bazzite (Fedora 41 ベース)** | 3.2+ | △ → 開発機の 3.4+ で動作確認済 | ✅ (現状) |

→ **Ubuntu / Debian / RHEL 系の主流 LTS で、F-IROH-40 が解消されない限り使えない**。

### 実環境ケーススタディ: nkwire

```
nkwire 環境:
  OS:      Ubuntu 24.04.4 LTS (Noble Numbat)
  OpenSSL: 3.0.13 30 Jan 2024
  CPU:     x86_64
  発症:    rustcrypto backend ビルド時に F-IROH-40 のコンパイルエラー
```

これは **2024 年リリースの最新 LTS** で発生している。つまり「古い環境だから」ではなく、**Linux サーバ運用の標準環境がそのまま影響を受ける**。Ubuntu LTS のサポート期間 (10 年) を考えると、**OpenSSL 3.5+ を標準パッケージで入手できるのは早くて Ubuntu 26.04 LTS (2026-04 以降)**。それまでは rustcrypto backend が事実上の必須選択肢。

## ロードマップへの影響

`project_nkcryptotool_roadmap.md` で確定したロードマップ:

```
[現状]
[1] chat CLI 完成 → [2] chat GUI (Slint) → [3] VPN PoC

[F-IROH-40 を反映した修正案]
[1a] F-IROH-40 (rustcrypto backend 復旧)  ← 即時最優先
  ↓
[1b] chat CLI 完成 (F-IROH-30 / F-IROH-20)
  ↓
[2] chat GUI (Slint)
  ↓
[3] VPN PoC
```

理由:

- **[1a] を最優先にすべき根拠**:
  - **nkwire (Ubuntu 24.04) で実機テストできない状態は不健全** (動作確認の幅が狭まる)
  - **Ubuntu / Debian / RHEL 系で利用するすべてのユーザがブロックされる**
  - F-IROH-40 は数行〜数十行の修正で済む見込み (fips203 の新 API 名に置換)
  - 修正後は bazzite 開発機で static binary をビルドして scp で nkwire へ持ち込み、即運用開始できる

- **[2] chat GUI (Slint mobile)**: iOS/Android では rustcrypto backend が事実上必須 (OpenSSL のクロスコンパイルは煩雑で実用に耐えない)。**F-IROH-40 が修正されない限り mobile 展開は不可能**。

- **[3] VPN PoC**: Linux 限定なら openssl で OK だが、static binary 配布等の柔軟性は失われる。

→ **F-IROH-40 は chat CLI 完成のステップ内で最優先で対処すべき**。F-IROH-30 / F-IROH-20 と並行ではなく **先**。

## CI が検出していない理由

GitHub Actions / 開発ワークフローで `cargo test` (= default feature = openssl) のみ実行している場合、rustcrypto 経路は **一度もビルドされない**。Phase 3 の負例テスト追加 (F-IROH-12 系) でもこのパスは網羅されていなかった。

→ **CI matrix に rustcrypto backend を追加すべき**。両 backend 並列ビルド/テストを走らせれば、この種の bug は即時検出可能。

## 修正方針 (別パーティ判断)

修正コードは出さず、選択肢のみ列挙:

### 方針 A: fips203 を最新版にアップデートし新 API に対応
- `Cargo.toml` の `fips203 = "0.4"` を最新に更新
- `cargo update -p fips203` で最新の minor / patch を確定
- 新 API (例えば `to_encaps_key()` 等想定) に置換
- 同時に `fips204` (ML-DSA) でも同じ問題が無いか確認

### 方針 B: fips203 の特定バージョンに pin
- 動作する最後のバージョンを特定 (例: `fips203 = "=0.4.0"` 等)
- 短期的には動くが、依存ライブラリの脆弱性修正を取りこぼすリスクあり

### 方針 C: keygen 時に公開鍵を保持する設計に変える
- `pqc_keygen_kem` の戻り値で公開鍵も返す (現状は seed しか返していない場合 / 既に返している場合は活用)
- 秘密鍵から公開鍵を再導出する `pqc_pub_from_priv_kem` 自体を削除
- 設計変更が必要だが、API 変更に強くなる

→ **方針 A (最新版アップデート + API 置換) が短期で最も筋が良い**。fips203 の API は ML-KEM の標準化 (FIPS 203) に追従しているので、メソッド名は IETF / NIST の用語に合わせて整理されているはず。

## 検証チェックリスト (修正後)

- [ ] `cargo build --release --no-default-features --features backend-rustcrypto` が通る
- [ ] `cargo test --release --no-default-features --features backend-rustcrypto` が全件 PASS
- [ ] `cargo test --release` (openssl default) が依然 17/17 PASS (リグレッションなし)
- [ ] `ldd target_rustcrypto/release/nk-crypto-tool` に `libssl` / `libcrypto` が含まれない
- [ ] rustcrypto 版バイナリで listener 起動 + openssl 版 connector で接続できる (相互運用)
- [ ] 逆方向 (openssl listener × rustcrypto connector) も接続できる

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体計画
- `IROH_MIGRATION_COMPLETION_REPORT.md` — Phase 3 で「全 4 フェーズ完了」を主張するも本問題を未検出
- `IROH_MIGRATION_VERIFICATION_REPORT.md` — F-IROH-39 を理由に「完了」保留を推奨。本件 F-IROH-40 でその判断がさらに正しかったことが裏付けられた
- `PHASE3_VERIFICATION_REPORT.md` — Phase 3 検証 (rustcrypto path は未検証)
- `project_nkcryptotool_roadmap.md` — chat CLI / GUI / VPN PoC の 3 段階ロードマップ。本件は CLI 完成の必須項目
- `CHAT_USAGE_GUIDE.md` — 2 端末チャット手順書 (現状 openssl backend を前提)
