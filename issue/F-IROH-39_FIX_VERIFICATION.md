# F-IROH-39 修正検証レポート — chat_loop の stdin EOF 無限ループ

作成日: 2026-05-06
対象: `F-IROH-39_FIX_REPORT.md` の修正主張に対する検証
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## エグゼクティブサマリ

**F-IROH-39 自体は推奨方針通り正しく修正されている**。実機回帰テストでも client.log が 2.5MB → 115B に縮小し、tight loop は完全に解消。

**ただし修正の副作用で `test_iroh_chat_loop_smoke` が FAIL する**。fix report は「ユニットテスト全件 PASS」を主張しているが、`cargo test --lib network` を実行すると 1/17 テストが panic する。

---

## ✅ 修正本体の確認

### コード変更 (実装通り)
`src/network/mod.rs:30-35, 80-111`

```rust
pub enum LineRead {
    Line,       // Got a full line ending with \n (or \r\n)
    PartialEof, // Got EOF but with some data before it
    Eof,        // Got EOF with 0 bytes
}
```

`read_line_secure` が `Result<LineRead>` を返すように変更。EOF 検知ロジック (line 89-95) も推奨方針 B (enum) 通り実装:

```rust
Ok(0) => {
    if total > 0 {
        return Ok(LineRead::PartialEof);
    } else {
        return Ok(LineRead::Eof);
    }
}
```

### chat_loop の制御フロー
`src/network/mod.rs:433-501`

- `LineRead::Eof` → `[System]: stdin closed.` 出力後 `break Ok(())` ✅
- `LineRead::Line && line_buf.is_empty()` → プロンプト再表示で `continue` ✅
- `LineRead::PartialEof` → 残データ送信後 `break Ok(())` ✅

診断レポート `F-IROH-39_DIAGNOSIS.md` の推奨設計と完全一致。

### 単体テスト 4 件
```
test network::tests::test_read_line_secure_eof          ... ok
test network::tests::test_read_line_secure_line         ... ok
test network::tests::test_read_line_secure_partial_eof  ... ok
test network::tests::test_read_line_secure_empty_line   ... ok
```

全 PASS。エッジケース (空行 / 改行なし EOF / 即 EOF) を網羅。

### 実機回帰テスト
2026-05-06 のテストと同じ環境で再実行:

| 指標 | 修正前 | 修正後 |
|---|---|---|
| client.log サイズ (EOF stdin で接続) | **2.5 MB** | **115 バイト** |
| `> ` の出力回数 | 数百万 | 0〜数個 |
| CPU 使用率 | 100% (1 コア占有) | 通常 |

→ **Tight loop 完全に解消**。

---

## ❌ 既存テストの回帰: `test_iroh_chat_loop_smoke` 失敗

**fix report は「ユニットテスト全件 PASS」を主張しているが、`cargo test --lib network` を実行すると以下のテストが FAIL する:**

```
thread 'network::iroh::tests::test_iroh_chat_loop_smoke' panicked at src/network/iroh.rs:867:9:
Chat loop should timeout on stdin

failures:
    network::iroh::tests::test_iroh_chat_loop_smoke

test result: FAILED. 16 passed; 1 failed; 0 ignored; 0 measured
```

### 原因

`test_iroh_chat_loop_smoke` (`iroh.rs:847-868`) は **F-IROH-39 のバグ挙動に依存**していた:

```rust
let client_res = tokio::time::timeout(Duration::from_secs(2), async {
    let processor = NetworkProcessor::new(client_config);
    processor.run_connect().await
}).await;
assert!(client_res.is_err(), "Chat loop should timeout on stdin");  // ← timeout を期待
```

| 状態 | chat_loop の挙動 | client_res | アサーション |
|---|---|---|---|
| 修正前 (バグあり) | stdin EOF で無限ループ | `Err(timeout)` | `is_err()` = true → PASS |
| 修正後 (正しい挙動) | stdin EOF で clean exit | `Ok(Ok(()))` | `is_err()` = false → **FAIL** |

つまり **このテストはバグそのものを検証していた**。

### サーバ側ログから挙動確認

```
--- Chat mode started ---
[System]: Connection closed by peer.
```

修正後の流れ:

1. クライアント・サーバとも chat_loop 開始
2. サーバの stdin が空 → `LineRead::Eof` 検知
3. サーバ clean exit → 接続クローズ
4. クライアント側が `Connection closed by peer` を受信して clean exit

→ **修正後の挙動はむしろ正しい**。テストの期待値が古い。

---

## 結論と推奨アクション

### F-IROH-39 修正の達成度

| 項目 | 状態 |
|---|---|
| 根本原因の解消 | ✅ 完全 |
| 推奨方針 (enum 導入) の採用 | ✅ 完全 |
| エッジケース網羅 (空行 / partial / 即 EOF) | ✅ 完全 |
| 新規単体テスト | ✅ 4/4 PASS |
| 実機回帰確認 | ✅ 2.5MB → 115B |
| **既存テストの整合性** | ❌ **`test_iroh_chat_loop_smoke` が FAIL** |
| fix report の主張との整合性 | ⚠️ **「全テスト PASS」は不正確** |

### 必要なアクション

1. **`test_iroh_chat_loop_smoke` の更新**: 修正後の正しい挙動 (clean exit) をアサートするよう書き換える。例:

   ```rust
   match client_res {
       Ok(Ok(_)) => {}                    // clean exit (正常)
       Ok(Err(e)) => panic!("..."),        // 内部エラー
       Err(_) => panic!("Should not timeout — stdin EOF should exit cleanly"),
   }
   ```

2. **fix report の「ユニットテスト全パス」の記述を訂正**: ビルド確認だけでなく `cargo test --lib network` の結果も記載すべき

3. **`test_iroh_chat_loop_smoke` を見直す機会**として、F-IROH-30 (実 chat_loop の暗号往復テスト) の追加もあわせて検討

---

### 重要な含意

このテスト失敗パターンは **F-IROH-33 / F-IROH-30 が示唆していた問題の典型例**:

> 「`test_iroh_chat_loop_e2e` (現 `_smoke`) は chat_loop の暗号処理を一切検証していない見かけ倒し」

**バグ検出を目的とすべきテストが、バグ挙動 (timeout) を期待値として固定化していた**ため、F-IROH-39 のような正当な修正で逆にテストが落ちる構造になっていた。

修正を進めるなら、`test_iroh_chat_loop_smoke` の改修と F-IROH-30 の本格テスト追加 (mock stdin/stdout で暗号往復を直接検証) を一緒に行うのが筋。

---

## 関連ドキュメント

- `F-IROH-39_DIAGNOSIS.md` — 根本原因分析と修正方針 4 案
- `F-IROH-39_FIX_REPORT.md` — 検証対象の修正完了レポート
- `PHASE3_VERIFICATION_REPORT.md` — F-IROH-39 の発見経緯
- `IROH_MIGRATION_VERIFICATION_REPORT.md` — F-IROH-39 を理由に「完了」保留を推奨
