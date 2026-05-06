# F-IROH-39 修正検証レポート v2 — chat_loop リファクタを含む追加検証

作成日: 2026-05-06
対象: `F-IROH-39_FIX_REPORT.md` (更新版) の修正主張に対する追加検証
前提: `F-IROH-39_FIX_VERIFICATION.md` (v1)
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## エグゼクティブサマリ

**F-IROH-39 は完全クローズ**。fix report 更新版で追加された「chat_loop が stdin を引数として受け取るようリファクタ」も実コードで確認済。テスト時に入力を求めて止まる現象は無く、無限ループも解消されている。

**ただし以下は次フェーズに持ち越し**:

1. **chat_loop の stdout は依然ハードコード** → テスト出力に `> > ` が leak し続ける
2. **メッセージ往復の真の E2E テスト未実装** (インフラは整ったが、mock stdin にメッセージを注入するテストは無い)
3. **`cfg!(test)` shortcut は継続** (F-IROH-20、特にファイル転送パスは release で `todo!()` panic 余地あり)

---

## 主張と検証の対応表

| Fix report の主張 | 実コード | 評価 |
|---|---|---|
| LineRead enum 導入 | `mod.rs:30-35` | ✅ 完全 |
| read_line_secure が `Result<LineRead>` | `mod.rs:80-111` | ✅ 完全 |
| **chat_loop が stdin を引数として受け取る** | `mod.rs:286-298` | ✅ **完全** (新規追加) |
| `LineRead::Eof` で clean exit | `mod.rs:435-438` | ✅ 完全 |
| `LineRead::PartialEof` で残データ送信後 exit | `mod.rs:497-500` | ✅ 完全 |
| `LineRead::Line` 空行で継続 | `mod.rs:439-444` | ✅ 完全 |
| 単体テスト 4 件追加 | `mod.rs:511-543` | ✅ 4/4 PASS |
| `test_iroh_chat_loop_smoke` 更新 | `iroh.rs:875-879` | ✅ 完全 |
| `cargo test --lib network` 全 PASS | 実行確認 | ✅ 17/17 PASS |

---

## ✅ 主要進展: chat_loop の stdin 抽象化

`src/network/mod.rs:286-298`

```rust
pub async fn chat_loop<R, W, SI>(
    mut stream_rx: R,
    mut stream_tx: W,
    mut stdin: SI,                    // ← 第3引数として stdin を受ける
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    is_server: bool,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
    SI: AsyncReadExt + Unpin + Send,  // ← ジェネリック
{
```

呼び出し側の切り替え (`iroh.rs / tcp.rs`):

```rust
#[cfg(not(test))]
let stdin = tokio::io::stdin();
#[cfg(test)]
let stdin = tokio::io::empty();
CommonProcessor::chat_loop(reader, writer, stdin, ...)
```

**意義**:
- F-IROH-30 / F-IROH-20 で繰り返し指摘していた「chat_loop の I/O ハードコード問題」の **半分**が解決
- mock stdin を注入できるインフラが整い、本格的な E2E テストが書ける土台ができた

---

## ⚠️ 残る問題

### 1. stdout は依然ハードコード

`chat_loop` 内部 (`mod.rs:268-272` ほか) で `tokio::io::stdout()` を直接使用:

```rust
let mut stdout = tokio::io::stdout();
let _ = stdout.write_all(b"> ").await;
let _ = stdout.flush().await;
```

→ テスト時に `> > ` が test output に leak し続ける (`cargo test --lib network` の出力で確認):

```
test network::tcp::tests::test_rx_task_abort_on_drop ... ok
> > test network::iroh::tests::test_iroh_chat_loop_smoke ... ok
```

これに対処するには chat_loop シグネチャに `SO: AsyncWriteExt` も追加する必要がある。**stdin の半分だけ対応した形**。

### 2. 真のメッセージ往復テスト未実装

`test_iroh_chat_loop_smoke` は現在も `tokio::io::empty()` を渡すだけで、**実際にメッセージを注入していない**。インフラは整ったが、活用されていない。

書ける状態になった具体例 (まだ書かれていない):

```rust
let stdin_mock = std::io::Cursor::new(b"hello world\n");  // メッセージ注入
// chat_loop 起動
// ピア側で "hello world" の暗号化メッセージを受信し復号できることをアサート
```

これが書かれて初めて F-IROH-30 (chat_loop の真の E2E テスト) がクローズできる。

### 3. `cfg!(test)` shortcut は継続 (F-IROH-20)

```rust
} else if cfg!(test) {
    writer.shutdown().await?;
    return Ok(());
} else {
    todo!("File transfer over Iroh")  // ← release で到達すると panic
}
```

ファイル転送パスは `cfg!(test)=false` で release ビルドに乗ると `todo!()` で panic 余地あり。チャットモードでは問題ないが、ファイル転送モードを release ビルドで使うと致命的。

これは Phase 3 で実装された production コード (line 419-421, 593-596) と並列に存在しているため実害は限定的だが、コードスメルとしては残存。

---

## テスト時に「入力を求める」バグは無い

ユーザの問い合わせ「テスト時に入力求められるバグあり？」への回答: **存在しない**。

検証結果:

| シナリオ | 挙動 |
|---|---|
| `cargo test` (stdin 通常) | F-IROH-39 修正で EOF 検知 → clean exit ✅ |
| `cargo test < /dev/null` | 同上 ✅ |
| TTY 上で `cargo test` 実行 | 同上 ✅ |
| 鍵生成 (`gen-sign-key`) のテスト | 該当テスト無し |

テスト出力に `> > ` が leak する現象は **stdout への書き込みが残っているだけで、ブロッキングしない**。

---

## 結論

### F-IROH-39 のクローズ判定

✅ **完全クローズ**。

- 根本原因 (read_line_secure の Ok(0) 二重意味) を enum 導入で解消
- chat_loop の stdin 抽象化 (推奨方針 B+α) を採用
- 単体 + 既存テスト + 実機回帰すべて PASS
- テスト時の入力ブロッキングなし

### 次フェーズの推奨アクション

1. **chat_loop の stdout も抽象化** (`> > ` leak 解消、F-IROH-30 の完全対応へ)
2. **メッセージ往復の真の E2E テスト追加** (mock stdin/stdout でメッセージ注入し暗号往復をアサート)
3. **`cfg!(test)` shortcut の解消** (F-IROH-20、特にファイル転送パス)

これらは F-IROH-39 とは独立した課題で、Iroh 移行プロジェクトの真の完了に向けた継続項目です。

---

## 関連ドキュメント

- `F-IROH-39_DIAGNOSIS.md` — 根本原因分析と修正方針 4 案
- `F-IROH-39_FIX_REPORT.md` — 検証対象の修正完了レポート (chat_loop リファクタ追記版)
- `F-IROH-39_FIX_VERIFICATION.md` — v1 検証 (chat_loop リファクタ前)
- `PHASE3_VERIFICATION_REPORT.md` — F-IROH-39 の発見経緯
- `IROH_MIGRATION_VERIFICATION_REPORT.md` — F-IROH-39 を理由に「完了」保留を推奨
