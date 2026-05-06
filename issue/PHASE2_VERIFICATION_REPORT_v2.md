# Phase 2 修正検証レポート v2 (Iroh 移行) — nkCryptoTool-rust

作成日: 2026-05-06
対象: `PHASE2_REMEDIATION_REPORT_FINAL.md` の修正主張に対する検証
前提:
- `PHASE2_VERIFICATION_REPORT.md` で指摘した F-IROH-26〜32 への修正が入った旨の報告
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## エグゼクティブサマリ

`PHASE2_VERIFICATION_REPORT.md` の指摘 7 件のうち 4 件 (F-IROH-29 / F-IROH-32 / F-IROH-27 / F-IROH-30) について修正主張があり、実コードを検証した結果:

- **F-IROH-29 / F-IROH-32**: 完全修正
- **F-IROH-27**: 部分改善 (panic 防止のみ、本質は fire-and-forget のまま)
- **F-IROH-30**: 形式上テストが追加されたが、**実態は chat_loop の暗号処理を一切検証していない見かけ倒し** (新規 F-IROH-33)

F-IROH-26 / F-IROH-28 / F-IROH-31 は remediation で言及なし、未対応継続。

**Phase 2 を完了扱いするには F-IROH-33 が引っ掛かる**。完了レポートの「QUIC ストリーム上でのフレーム処理、暗号化、タイムアウト制御が正しく機能することを実証しました」という主張は、現状の `test_iroh_chat_loop_e2e` では裏付けられない。

---

## 修正状況サマリ

| 指摘 | 修正主張 | 実コード |
|---|---|---|
| F-IROH-29 (silent fail) | ✅ ヘルパー関数化 | ✅ **完全修正** |
| F-IROH-32 (test-threads) | ✅ serial_test 導入 | ✅ **完全修正** |
| F-IROH-27 (EndpointGuard) | ✅ ランタイム配慮 | ⚠️ **部分改善** (panic は防げるが fire-and-forget) |
| F-IROH-30 (chat_loop テスト) | ✅ E2E 追加 | ❌ **見かけ倒し** (新規 F-IROH-33) |
| F-IROH-26 (target_enc_fp dead code) | (言及なし) | ❌ 未対応 |
| F-IROH-28 (multi-client 認証) | (言及なし) | ❌ 未対応 |

---

## ✅ 修正確認

### F-IROH-29: 完全修正
`src/network/iroh.rs:102-117, 131-138`

```rust
fn get_pqc_fingerprint(&self, path: &str, algo: &str, is_dsa: bool) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path).map_err(|e| CryptoError::FileRead(...))?;
    let pem = std::str::from_utf8(&bytes).map_err(...)?;
    // ... 全エラーが ? で伝搬
    Ok(Sha3_256::digest(&raw_pub).into())
}

// 呼び出し側
let sign_fp = self.config.signing_privkey.as_ref()
    .map(|path| self.get_pqc_fingerprint(path, &self.config.pqc_dsa_algo, true))
    .transpose()?;
```

`Option::map` + `Result::transpose` + `?` で綺麗。passphrase 不一致や鍵ファイル不在は確実にエラー昇格。

### F-IROH-32: 完全修正
`Cargo.toml:32` で `serial_test = "3.0"`、全 6 テストに `#[serial]` 付与 (line 557, 596, 658, 716, 773, 828)。`cargo test` をデフォルトで叩いても並列衝突しない。

---

## ⚠️ 部分修正

### F-IROH-27: panic は防げるが本質的には fire-and-forget のまま
`src/network/iroh.rs:23-35`

```rust
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let endpoint = self.0.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                endpoint.close().await;
            });
        }
    }
}
```

改善点:
- `Handle::try_current()` でランタイム不在時の panic を防止 ✅

依然として残る問題:

- **detached task の完了保証なし**: spawn 後にプロセス終了/runtime drop されると close は途中で打ち切られる
- **process exit との race**: `main()` 終了直前で guard が drop すると spawn される close は実行機会を失う可能性
- 「Drop ガードによる確実な解放」という当初の主張とは厳密には一致しない

実用上ベストエフォートとしては機能するが、relay session のクリーンクローズ通知が省かれる余地は残る。

---

## ❌ 見かけ倒し修正 (新規 F-IROH-33)

### F-IROH-33 🟠: `test_iroh_chat_loop_e2e` は実質的に chat_loop を検証していない
`src/network/iroh.rs:827-862`

```rust
#[tokio::test]
#[serial]
async fn test_iroh_chat_loop_e2e() {
    reset_state();
    // ... server/client setup with chat_mode=true ...

    let client_res = tokio::time::timeout(Duration::from_secs(2), async {
        let processor = NetworkProcessor::new(client_config);
        processor.run_connect().await
    }).await;

    // Should timeout because chat_loop waits for stdin
    assert!(client_res.is_err(), "Chat loop should wait for stdin and timeout");
}
```

**重大な誤誘導**: アサーションが `is_err()` (= タイムアウト) を**期待**している。これが意味するのは:

- chat_loop が「stdin を待つループに入った」だけが検証されている
- 実際のメッセージ往復、暗号化、復号、framing、nonce/replay 検出は **一度も実行されない**
- 仮に暗号化ロジックが完全に壊れていても、chat_loop が起動さえすればこのテストは PASS する
- 仮に chat_loop で正常にメッセージ交換ができて exit すると `client_res = Ok(())` → アサーション失敗 → **正常動作するとテストが落ちる構造**

完了レポートの主張:
> 「QUIC ストリーム上でのフレーム処理、暗号化、タイムアウト制御が正しく機能することを実証しました」

実態とは乖離している。実証されているのは「chat_loop 起動 + stdin 待機」のみ。F-IROH-30 は**形式上テストが追加されたが、本質的に未対応**。

本来必要なのは:

- chat_loop を `(R: AsyncRead, W: AsyncWrite)` に対する純関数として切り出すか、テスト用に stdin/stdout を差し替え可能にする
- mock reader/writer で平文を注入し、ピア側で復号できることをアサート
- replay 検出: 同じ packet を 2 回送って 2 回目が拒否されることをアサート
- malformed packet: tag 改竄で復号失敗をアサート

---

## 引き継ぎ未対応事項

### F-IROH-26: `target_enc_fp` がデッドコード継続
remediation report で言及なし。`run_connect` 内で `target_enc_fp` を設定するが、これを照合するコードは存在しない。サーバの ML-KEM 公開鍵はハンドシェイクで送信されないため、構造的に検証不能。

→ ticket フォーマットには `pqc_enc_fp` フィールドがあるが、現状は飾り。文書化または機能完成 (Phase 3 のファイル転送と紐付け?) が必要。

### F-IROH-28: multi-client 認証不能継続
remediation report で言及なし。`signing_pubkey=None` + allowlist + `allow_unauth=true` の組み合わせが全クライアント拒否になる構造。プロトコル拡張 (クライアントが DSA pubkey を送信) が必要。

### F-IROH-31: relay メタデータ漏洩
Phase 3 スコープ通り未対応。production の `relay_mode` が `Default` のまま。

### F-IROH-20: `cfg!(test)` 混入
未対応。Phase 3 でファイル転送実装時に解消想定。

### その他継続中

- F-IROH-03 (ALPN ハードコード)
- F-IROH-08 (spawn_blocking 内シークレット寿命)
- F-IROH-11 (複数 ALPN)
- F-IROH-13 (`_s2c_iv` / `_c2s_iv` 未使用)
- F-IROH-17 (NodeId rotation で cooldown 回避)
- F-IROH-21 (allowlist の role 非対称)

---

## 優先度サマリ

1. **F-IROH-33** 🟠 (chat_loop テストの見かけ倒し) — 完了レポートの主張と実態が乖離。即時対処すべき。実テストの追加は構造的に難しい (stdin の注入が必要) ため設計議論が必要
2. **F-IROH-26** 🟡 (target_enc_fp dead code) — Phase 3 で意図を明確化
3. **F-IROH-27** 🟡 (Drop guard) — 実用上問題は小さい、Phase 3 で再検討
4. **F-IROH-28** — Phase 3 でプロトコル拡張検討

---

## 結論

**Phase 2 を完了とするには F-IROH-33 が引っ掛かる**。完了レポートの「QUIC ストリーム上でのフレーム処理、暗号化、タイムアウト制御が正しく機能することを実証しました」という主張は、現状の `test_iroh_chat_loop_e2e` では裏付けられない。

このテストは「chat_loop が起動するか」のスモークテストとしては有用だが、E2E 検証としては機能していない。Phase 3 移行前にここを補強するか、少なくとも完了レポートの記述を実態に合わせて修正する (「chat_loop 起動の確認」とする) のが筋。

---

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体計画
- `PHASE1_*` — Phase 1 関連 (完了 / 修正サイクル / 検証サイクル)
- `PHASE2_COMPLETION_REPORT.md` — Phase 2 完了レポート
- `PHASE2_REMEDIATION_REPORT_FINAL.md` — 検証対象の修正完了レポート
- `PHASE2_VERIFICATION_REPORT.md` — 前回 (v1) の Phase 2 統合検証
