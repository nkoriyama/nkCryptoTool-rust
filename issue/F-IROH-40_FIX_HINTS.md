# F-IROH-40 修正ヒント — fips203 API 調査結果と 4 つのアプローチ

作成日: 2026-05-07
対象: F-IROH-40 (rustcrypto backend ビルド不可) の修正方針提示
役割: 診断と方針提示のみ (実装は別パーティ)
前提: `F-IROH-40_RUSTCRYPTO_BUILD_BROKEN.md`

---

## 重要な発見

**fips203 0.4.3 の `DecapsKey` には公開鍵を取り出す API が存在しません**。

`/home/bazzite/.cargo/registry/src/index.crates.io-*/fips203-0.4.3/src/traits.rs` を全文確認した結果:

- `KeyGen::try_keygen()` は **`(EncapsKey, DecapsKey)` 両方を同時に返す**
- `DecapsKey` 単体から `EncapsKey` を導出するメソッドは **無い**
- `SerDes` trait は `into_bytes` / `try_from_bytes` のみで、構造体間変換は不可

つまり `sk.get_public_key()` という API は **過去のバージョンにも存在しなかった可能性が高い** (もしくは 0.3 系にあって 0.4 で削除)。

これは crate の設計思想で、「秘密鍵から公開鍵を再導出するのは推奨しない」「両方とも keygen 時に保管しろ」というスタンス。

## 4 つの修正アプローチ

### アプローチ 1: 設計変更で `pqc_pub_from_priv_kem` 自体を不要にする (王道)

**最も筋が良い**。call site (`iroh.rs:127-142` の指紋生成コード) は「秘密鍵だけ持っていて、そこから公開鍵指紋を計算する」前提だが、これを変える。

選択肢:

#### A-1: ユーザの鍵保存形式を「秘密鍵 + 公開鍵」のペアにする (推奨)
- `~/nkct/alice/private_sign_pqc.key` の隣に `public_sign_pqc.key` (既に作られている!)
- `pqc_pub_from_priv_kem` の代わりに **公開鍵ファイルを直接読む** ように変更
- listener 起動時の指紋計算は public key file から

#### A-2: PKCS#8 envelope に公開鍵も含める
- PKCS#8 v2 (RFC 5958) は OneAsymmetricKey で `publicKey [1] PublicKey OPTIONAL` を含められる
- 既に `pkcs8 = { version = "0.10", features = ["encryption"] }` 依存済み
- 保存時に publicKey フィールドを書き込み、読み込み時に取り出すだけ

→ **A-1 が最も簡単 (10-20 行レベルの変更)**。ファイル I/O が増えるだけ。

### アプローチ 2: dk バイト列から ek を offset 抽出 (fragile)

**FIPS 203 §7.2 の dk 構造**を利用:

```
dk = dk_pke || ek || H(ek) || z
```

| アルゴリズム | k | dk_pke size | ek size | ek offset |
|---|---|---|---|---|
| ML-KEM-512 | 2 | 768 | 800 | 768 |
| ML-KEM-768 | 3 | 1152 | 1184 | 1152 |
| ML-KEM-1024 | 4 | 1536 | 1568 | 1536 |

```rust
// 概念コード (実装は別パーティに任せる)
let ek_offset = match algo {
    "ML-KEM-512" => 768,
    "ML-KEM-768" => 1152,
    "ML-KEM-1024" => 1536,
    _ => return Err(...)
};
let ek_len = match algo {
    "ML-KEM-512" => 800,
    "ML-KEM-768" => 1184,
    "ML-KEM-1024" => 1568,
    _ => return Err(...)
};
let ek_bytes = &raw_priv_decoded[ek_offset..ek_offset + ek_len];
```

**注意**: `unwrap_pqc_priv_from_pkcs8` が返す raw_priv の形式が「FIPS 203 純粋な dk format」かどうかを確認が必要。PKCS#8 デコード後にラッパーが残っているかもしれない。

**リスク**: fips203 が将来 dk のシリアライズ形式を変えると壊れる。テスト必須。

### アプローチ 3: keygen 時の seed を保存して再生成

`KeyGen::keygen_from_seed(d, z)` を使って public key を再構築:

```rust
let (ek, _dk) = MlKem768::keygen_from_seed(d_seed, z_seed);
let ek_bytes = ek.into_bytes();
```

→ ただし `pqc_keygen_kem(algo)` が返している `seed` が `d || z` なのか別物なのか調査必要。`Cargo.toml` に `rand_core = { version = "0.6", features = ["getrandom"] }` があるので、独自の seed 形式かもしれない。

`rustcrypto_impl.rs` の `pqc_keygen_kem` を見れば判明。

### アプローチ 4: rustcrypto では unimplemented にして API を揃える (最後の手段)

```rust
#[cfg(feature = "backend-rustcrypto")]
pub fn pqc_pub_from_priv_kem(_algo: &str, _raw_priv: &[u8]) -> Result<Vec<u8>> {
    Err(CryptoError::Parameter(
        "pqc_pub_from_priv_kem not supported with rustcrypto backend; please supply public key separately".to_string()
    ))
}
```

そして call site (iroh.rs) で「rustcrypto では別途 public key file を渡す」処理を追加。

→ **A-1 と組み合わせると現実的**。

---

## 推奨: A-1 (秘密鍵 + 公開鍵のペアファイル運用)

### なぜ A-1 が最良か

1. ユーザは既に `~/nkct/alice/public_sign_pqc.key` を作っている (CHAT_USAGE_GUIDE.md 通りの運用)
2. 秘密鍵のすぐ隣にあるのを読むだけ → コード追加は最小限
3. **fips203 / fips204 両方に同じパターン**で適用可能 (DSA も同じ問題が起きる前にすべき)
4. 公開鍵を別ファイルで持つのは PGP / SSH 等の慣習に沿う
5. crate のバージョンアップに対して耐久力あり

### 具体的な変更ポイント

| ファイル | 変更内容 |
|---|---|
| `src/config.rs` | `user_pubkey: Option<String>` フィールド追加 (KEM 公開鍵ファイルパス) |
| `src/main.rs` | CLI に `--user-pubkey` 追加 (`--my-enc-pubkey` エイリアスも検討) |
| `src/network/iroh.rs:127-142` | `get_pqc_fingerprint` を「秘密鍵から導出」ではなく「公開鍵ファイルを読んで SHA3-256」に変更 |
| `src/backend/rustcrypto_impl.rs:625-645` | `pqc_pub_from_priv_kem` を削除 (unused でコンパイル成功)、または unimplemented でスタブ化 |
| `src/backend/openssl_impl.rs` | 同じくスタブ化 (両 backend で API を揃える) |

### 影響を受ける CLI 利用パターン

修正前 (現状):
```bash
--signing-privkey ~/nkct/alice/private_sign_pqc.key \
--user-privkey    ~/nkct/alice/private_enc_pqc.key   # 秘密鍵だけ
```

修正後:
```bash
--signing-privkey ~/nkct/alice/private_sign_pqc.key \
--signing-pubkey  ~/nkct/alice/public_sign_pqc.key   # 自分の公開鍵も指定
--user-privkey    ~/nkct/alice/private_enc_pqc.key \
--user-pubkey     ~/nkct/alice/public_enc_pqc.key    # 自分の公開鍵も指定
```

→ ユーザは既に両方のファイルを持っているので運用上の負担なし。`CHAT_USAGE_GUIDE.md` の手順だけ更新が必要。

---

## 修正前に確認すべき点

### 1. fips203 0.4 系のリリースノート確認

```bash
# crates.io 公式: https://crates.io/crates/fips203
# repo: https://github.com/integritychain/fips203 (推定)
```

`0.4.0 → 0.4.3` で何が変わったか。過去に `get_public_key` があったかどうか。

### 2. `pqc_keygen_kem` の seed 形式 (`rustcrypto_impl.rs` 内)

```bash
grep -A20 "pub fn pqc_keygen_kem" \
  /var/home/bazzite/ドキュメント/src/nkCryptoTool-rust/src/backend/rustcrypto_impl.rs
```

これがアプローチ 3 を採るかの判断材料。現在 `unwrap_pqc_priv_from_pkcs8` の戻り値が何の bytes か (raw FIPS 203 dk か独自形式か) も同時に確認。

### 3. `pqc_pub_from_priv_dsa` (DSA 版) は通っている理由

```bash
grep -n "pqc_pub_from_priv_dsa" \
  /var/home/bazzite/ドキュメント/src/nkCryptoTool-rust/src/backend/rustcrypto_impl.rs
```

fips204 にも `get_public_key` がない場合、その関数がコンパイル成功している理由を確認 (使われていないだけかもしれない)。

---

## 検証方法 (修正後)

### コンパイル

```bash
CARGO_TARGET_DIR=target_rustcrypto cargo build --release \
  --no-default-features --features backend-rustcrypto
```

### テスト

```bash
CARGO_TARGET_DIR=target_rustcrypto cargo test --release \
  --no-default-features --features backend-rustcrypto
```

期待: 全テスト PASS (openssl 版の 17 件と同等)。

### 相互運用テスト

bazzite (openssl) でビルドした listener と nkwire (rustcrypto) でビルドした connector が接続できる、その逆も:

```bash
# bazzite (openssl):
./target/release/nk-crypto-tool --chat --listen 0.0.0.0:0 \
  --signing-privkey alice.priv --signing-pubkey alice.pub \
  --user-privkey alice_kem.priv --user-pubkey alice_kem.pub \
  --transport iroh

# nkwire (rustcrypto):
./target_rustcrypto/release/nk-crypto-tool --chat --connect 'nkct1...' \
  --signing-privkey bob.priv --signing-pubkey bob.pub \
  --user-privkey bob_kem.priv --user-pubkey bob_kem.pub \
  --transport iroh
```

---

## ロードマップへの位置付け

`project_nkcryptotool_roadmap.md` の最優先項目:

```
[1a] F-IROH-40 修正 (本ドキュメントのアプローチ A-1 を推奨)
  ↓ Ubuntu 24.04 LTS / nkwire で動作確認
[1b] F-IROH-30 / F-IROH-20 (chat CLI 完成)
  ↓
[2] chat GUI (Slint)
  ↓
[3] VPN PoC
```

A-1 採用なら:
- 修正規模: 30-50 行
- テスト追加: 既存テストに `--user-pubkey` を追加するのみ
- ドキュメント更新: `CHAT_USAGE_GUIDE.md` のコマンド例 (Step 4-5)

---

## 関連ドキュメント

- `F-IROH-40_RUSTCRYPTO_BUILD_BROKEN.md` — エラー詳細と影響範囲
- `IROH_MIGRATION_VERIFICATION_REPORT.md` — F-IROH-39 / F-IROH-40 を理由に「真の完了」保留
- `CHAT_USAGE_GUIDE.md` — 修正後にコマンド例の更新が必要
- `project_nkcryptotool_roadmap.md` (memory) — 修正の最優先位置付け
- `project_nkcryptotool_environments.md` (memory) — bazzite / nkwire の build 環境制約
