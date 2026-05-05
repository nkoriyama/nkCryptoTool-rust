# nkCryptoTool-rust 現状の問題点まとめ (v56 時点)

**日付**: 2026-05-05
**対象**: nkCryptoTool-rust v56 (FINAL_REMEDIAL_REPORT_v56 反映済み)
**目的**: v56 時点で**未解決のまま残っている問題**を全カテゴリで整理

---

## 概要

v44 → v56 の 13 サイクルでコア機能の致命バグはほぼすべて解消した。OpenSSL backend で PQC keygen + sign/verify/encap/decap が動作し、RustCrypto backend と完全に相互運用できる状態に到達。ただし以下の問題が残存している。

| カテゴリ | 件数 | 重大度 |
|---|---|---|
| v56 で新規発生 | 6 件 | 🔴 致命 〜 🟡 軽微 |
| 既存攻撃シナリオ未対応 | 4 件 | 🟠 中 〜 🟡 軽微 |
| 設計レベル長期課題 | 4 件 | 🟠 中（先送り中） |
| 検証プロセスの問題 | 2 件 | 🟡 軽微 |

---

## 🔴 致命的：F-56-1 — OpenSSL backend `extract_raw_private_key` のサイレント失敗（F-50-1 再発）

**標的**: `src/backend/openssl_impl.rs::extract_raw_private_key`

```rust
if let Some(pass) = passphrase {                           // ← 外側 passphrase ガード
    if let Ok(pki) = pkcs8::EncryptedPrivateKeyInfo::from_der(priv_der) {
        let decrypted = pki.decrypt(pass).map_err(...)?;
        return Ok(Zeroizing::new(decrypted.as_bytes().to_vec()));
    }
}
Ok(Zeroizing::new(priv_der.to_vec()))                      // ← フォールスルー
```

**実害**: 暗号化 PEM + `passphrase = None` のとき、暗号文がそのまま raw_priv として返る。後段の `unwrap_pqc_priv_from_pkcs8` が暗号文を「鍵」と誤認識して確率的な誤動作を起こす。

**根本原因**: F-50-1 で v50 → v51 に修正されたバグの完全な再発。RustCrypto backend には正しい実装（`from_der` 判定が先 + passphrase なしは明示エラー）があるが、OpenSSL backend にコピーされなかった。

**修正**: 5 行差し替えで完了。RustCrypto backend と同等のロジックに揃える。

---

## 🟠 重大：F-56-2 — `pqc_keygen_dsa` が KEM 用 seed パラメータを参照

**標的**: `openssl_impl.rs:649-664`, `614-635`

```rust
pub fn pqc_keygen_dsa(algo: &str) -> Result<...> {
    pqc_keygen_kem(algo)   // ← KEM 用関数を流用
}
```

`pqc_keygen_kem` は seed 抽出で `OSSL_PKEY_PARAM_ML_KEM_SEED` を参照。ML-DSA に対しては失敗 → `seed = None`。

**実害**:
- 機能的には現状動作（`seed = None` なので副作用なし）
- ML-DSA seed (`xi`) を取得できない
- 将来 OpenSSL が `OSSL_PKEY_PARAM_ML_DSA_SEED` を露出した際に**この共用実装ではキャッチできない**
- 関数名と動作の乖離で保守性が低下

**修正**: KEM/DSA で別 seed パラメータ名を引数化したヘルパーに分離、または `pqc_keygen_dsa` を独立実装化。

---

## 🟠 中：F-56-3 — PQC 復号速度がレポート主張より低い

**観測値** (2.0 GiB tmpfs):
- OpenSSL PQC encrypt: **3.35 GiB/s** ≈ レポート主張 ~3.1 GiB/s
- **OpenSSL PQC decrypt: 2.53 GiB/s** ← レポート主張 ~3.1 GiB/s より約 18% 低
- OpenSSL Hybrid encrypt: 3.41 GiB/s
- **OpenSSL Hybrid decrypt: 2.76 GiB/s**
- (参考) OpenSSL ECC decrypt: 3.29 GiB/s — PQC のような低下なし

**実害**: README/最終レポートのベンチ値が**18% 楽観的**。重大な性能問題ではないが、表記不一致は信頼性を損なう。

**修正案**:
- 安定性確認のため複数回計測 → 平均値でレポート更新
- README ベンチ表で encrypt と decrypt を分けて記載

---

## 🟠 重大：F-56-A — `extract_raw_private_key` が両 backend で重複実装（共通化されていない）

**標的**: `src/backend/openssl_impl.rs::extract_raw_private_key` および `src/backend/rustcrypto_impl.rs::extract_raw_private_key`

両者は**ほぼ同じロジック**だが別々に実装されているため、片方に修正を入れても他方へ伝播しない。F-56-1 はこの構造的問題が表面化した結果。

**修正**: `utils.rs` に backend 非依存の `extract_raw_private_key` を集約し、両 backend からはそれを呼ぶ。`pkcs8` クレートはどちらの feature でも有効。

```rust
// utils.rs (新設)
pub fn extract_raw_private_key(priv_der: &[u8], passphrase: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    use pkcs8::der::Decode;
    if let Ok(pki) = pkcs8::EncryptedPrivateKeyInfo::from_der(priv_der) {
        let pass = passphrase.ok_or_else(|| ...)?;
        let decrypted = pki.decrypt(pass).map_err(...)?;
        return Ok(Zeroizing::new(decrypted.as_bytes().to_vec()));
    }
    Ok(Zeroizing::new(priv_der.to_vec()))
}
```

---

## 🟡 軽微：v56 で発生

### F-56-4: 「全 24 のテスト」表記が実測と乖離

実測: default features で 17、`backend-rustcrypto` のみで 20。最終レポート §3.1 の「全 24」は誇張。

### F-56-5: `pkey_from_raw` の戻り値が `PKey<Private>` 固定

```rust
fn pkey_from_raw(...) -> Result<PKey<openssl::pkey::Private>>
```

公開鍵の場合も `Private` 型で返すため、Rust の型レベル安全性が崩れる。FFI ポインタは同じなので動作上は問題なし。

### F-56-6: `EVP_PKEY_get_octet_string_param` 後に Vec を truncate していない

`sk_len` が 2 回目の呼び出しで上書きされる可能性に備えて `sk.truncate(sk_len)` を追加すべき。OpenSSL 実装上は通常一致するが保守的には必要。

---

## 🟠 既存攻撃シナリオの未対応（v44 から残存）

### 1. key_dir パストラバーサル（v44 攻撃⑧）

**未対応**: `--key-dir` の検証なし。`secure_write` の `O_NOFOLLOW + 0o600` で安全に書けるが、**意図しない場所**に鍵ファイルが配置されるリスクは残る。

### 2. cached_signing_key の長期メモリ常駐（v44 攻撃⑨ — 7 サイクル未対応）

`mlock` で swap 防止までは実装済（v55）。プロセス全期間メモリ常駐する設計は維持されており、**ptrace / `/proc/<pid>/mem` 経由のメモリスクレイピングには無防備**。

緩和策（lazy ロード方式での揮発化）は未実装。

### 3. 信頼ピアの長時間セッション攻撃 (F-55-5)

`peer_allowlist` 内の悪意ある内部 peer が `IDLE_TIMEOUT - 1秒` ごとにダミー packet を送って 2 時間まで接続維持可能。CHAT_SESSION_TIMEOUT (2h) で切断後も即座に再接続可能 (60秒 cooldown 後)。

**未対応**: peer ごとの 1 日累計接続時間制限、ダミー packet 検出。

### 4. `peer_allowlist` の運用支援機能（F-55-1, F-55-3, F-55-4）

- フィンガープリント計算用 `nk-crypto-tool fingerprint` サブコマンドが**未実装**
- 許可リスト hot-reload なし（鍵失効に再起動必要）
- 許可リストファイルのパーミッション検証なし

---

## 🟠 設計レベル・長期課題

### A. ASN.1 構造的パーサへの未移行

**現状**: `unwrap_pqc_priv_from_pkcs8` 等で**ヒューリスティックなバイト走査**を継続。
- F-44-2 から複数サイクルで「中期目標」と位置付け
- 過去に複数の確率的バグの原因（F-43-1, F-45-1）

**対策**: `pkcs8` クレートまたは `der` クレートへの移行（既に `extract_raw_private_key` で `pkcs8::EncryptedPrivateKeyInfo` は使用中）。

### B. グローバルレート制限の未実装

**現状**: 個別 cooldown のみ。**システム全体の秒間接続数制限**がない。
- F-46-4 から **9 サイクル連続「今後の検討」**
- ボットネット規模の攻撃に無防備

**対策**: トークンバケットアルゴリズムによるグローバル制限。最終レポートでも「今後の推奨事項」として明記。

### C. peer-pubkey 多重スロットの未実装

**現状**: チャットは単一スロット (`CHAT_ACTIVE`)。
- 同時に複数ユーザーがチャットできない
- 一人が長時間占有できる

**対策**: peer-pubkey ごとに独立したスロット管理。

### D. F-56-A バックエンド共通ロジックの集約（再掲、上記 §F-56-A 参照）

---

## 🟡 検証プロセスの問題

### 1. テストカバレッジの非対称（F-49-6 由来、v56 でも一部残存）

統合テスト `test_preload_encrypted_pem` は依然 `#[cfg(feature = "backend-rustcrypto")]` のみゲート。OpenSSL backend で**暗号化 PEM の preload テストが存在しない**ため、F-56-1 のような OpenSSL backend 固有のバグが**テストで自動検出されない**。

**対策**: OpenSSL backend 用の対応テストを `tests/security.rs` に追加。

### 2. レポート主張と実装の精緻な一致確認

過去の典型例（F-45 「全件 PASS」虚偽、F-48-3 「F-47-3 緩和」虚偽、F-49-1 復号せず暗号文を返す、F-52-1 ephemeral 鍵を long-term identity として扱う、F-54-1 PBES2 OID で ECC 機能退行）。

v56 でも:
- F-56-1: 「F-50-1 サイレント失敗」を OpenSSL backend で再発
- F-56-3: ベンチ値の表記が 18% 楽観的
- F-56-4: テスト数 24 件表記が実測 17-20 と乖離

これらは**「実装ロジックを文章で確認する」**段階を超え、**「該当機能の自動テストが PASS していることを必須化」**するプロセスでしか防げない。

---

## 修正優先度マトリクス

### 即時対応必須（重大バグ修正、数行で実装可能）

| 優先 | 問題 | 修正規模 |
|---|---|---|
| 🔴 1 | F-56-1: OpenSSL backend extract_raw_private_key の論理逆転 | 5 行 |
| 🔴 2 | F-56-A: extract_raw_private_key を utils に集約 | 30 行（リファクタ） |

### 中期対応（v56 の精度向上）

| 優先 | 問題 | 修正規模 |
|---|---|---|
| 🟠 3 | F-56-2: `pqc_keygen_dsa` を独立実装化 | 50 行 |
| 🟠 4 | F-56-3: ベンチ再測定 + README 修正 | 文書 |
| 🟠 5 | F-55-1: `nk-crypto-tool fingerprint` サブコマンド | 30-50 行 |
| 🟠 6 | F-49-10/F-55-7: cached_signing_key の lazy ロード化 | 数十行 |
| 🟠 7 | F-55-3/4: peer_allowlist の hot-reload + ファイル保護 | 50-100 行 |

### 長期対応（アーキテクチャ拡張）

| 優先 | 問題 | 規模 |
|---|---|---|
| 🟡 8 | ASN.1 構造的パーサへの完全移行 | 数百行 |
| 🟡 9 | グローバルトークンバケット | 中規模 |
| 🟡 10 | peer-pubkey 多重スロット | 中〜大規模 |

### プロセス改善

| 優先 | 問題 | 規模 |
|---|---|---|
| 🟡 11 | OpenSSL backend での暗号化 PEM 統合テスト追加 | 30 行 |
| 🟡 12 | 「PASS 主張」の自動検証必須化 | プロセス |
| 🟡 13 | バックエンド非依存ロジックの `utils` への集約 | リファクタ |

---

## 全体評価

### 達成された主要成果（v44 → v56）

- **暗号機能の根本動作**: F-43-1 (ML-KEM 機能停止)、F-45-1 (確率的署名失敗)、F-49-1 (preload で復号せず) 等の致命バグ解決
- **認証アーキテクチャ**: `allow_unauth=false` デフォルト化、PeerId::Pubkey 導入、peer_allowlist 実装
- **DoS 防御**: cooldown、parking_lot::Mutex、HANDSHAKE_TIMEOUT、IDLE_TIMEOUT、CUMULATIVE_TIMEOUT 多層化
- **OpenSSL backend で PQC 完全動作** (v56) — 13 サイクル積み残しの最後の課題が解決
- **クロスバックエンド相互運用**: PQC/Hybrid/ECC 全モードで実証済 (5/5 PASS)
- **ベンチで OpenSSL PQC が ~3.4 GiB/s (encrypt)** を達成

### 未解決の本質的課題

- **F-56-1 (新規)**: F-50-1 の OpenSSL backend での再発 — **即時修正可能**
- **F-56-A**: backend 共通ロジックの分離不足 — リファクタで解消可能
- **F-46-4 (9 サイクル連続)**: グローバルレート制限の根本対策
- **F-49-10 (8 サイクル)**: passphrase 長期常駐
- **設計拡張**: peer 多重スロット、ASN.1 構造的パーサ

### 結論

13 サイクルの集中的な修正で**実装上の致命バグはほぼ解消**し、**機能的にはほぼ完成**。残るのは:

1. **F-56-1 の即時修正**（致命だが 5 行で完了）
2. **F-56-A のリファクタ**（再発防止のための構造的対策）
3. **設計レベルの拡張**（運用規模拡大時に必要）

**現時点で個人〜小規模グループ用途では実運用可能**。**公開サーバ運用には F-46-4 等のレート制限と F-55-5 の信頼ピア制御が必須**。

修正サイクルとしては**「致命バグ修正期」から「機能拡張期」へ移行する転換点**。F-56-1 を解決すれば、コード単体での脆弱性修正フェーズは事実上終了し、運用ベストプラクティス整備や監視・ログ機能追加へ重点が移る。
