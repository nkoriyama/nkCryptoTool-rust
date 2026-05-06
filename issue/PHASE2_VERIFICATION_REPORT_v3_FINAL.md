# Phase 2 修正検証レポート v3 (最終) — nkCryptoTool-rust

作成日: 2026-05-06
対象: `PHASE2_REMEDIATION_REPORT_v3_FINAL.md` の修正主張に対する検証
前提:
- `PHASE2_VERIFICATION_REPORT.md` (v1)
- `PHASE2_VERIFICATION_REPORT_v2.md` (v2)
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## エグゼクティブサマリ

**Phase 2 のクローズ条件は満たされた**と判断できる。

主要修正 (F-IROH-29 / F-IROH-32 / F-IROH-26 / F-IROH-27 / F-IROH-33) は完了または「スコープ明文化」で適切に収束。残存する技術的負債は全て Phase 3 のスコープに接続されている。

唯一の注釈は **F-IROH-34** (新規):

- explicit `close().await` への刷新は、cancel/panic 経路で旧版 (Drop guard + spawn) より弱くなる
- remediation report の「エラー発生時や早期 return 時も含め…確実に終了することを保証」は若干誇張
- 実用上の影響は小さく、Phase 3 で再評価可能

---

## 修正状況サマリ

| 指摘 | 修正主張 | 実コード |
|---|---|---|
| F-IROH-27 (Drop guard) | ✅ explicit close.await に刷新 | △ **方向性転換** (F-IROH-34 参照) |
| F-IROH-33 (chat_loop test 見かけ倒し) | ✅ スモークテストとして再定義 | ✅ **適切な範囲修正** |
| F-IROH-26 (target_enc_fp) | ✅ Phase 3 への意図的延期と明記 | ✅ **文書化で収束** |
| F-IROH-28 (multi-client) | ✅ Phase 3 スコープ | ✅ 計画通り |
| F-IROH-31 (relay) | ✅ Phase 3 スコープ | ✅ 計画通り |

---

## ✅ 適切に収束した項目

### F-IROH-33: スモークテスト宣言で「主張と実態の乖離」が解消
remediation report で明記:

> 「現状のテストは `stdin`/`stdout` に依存しているため、メッセージ内容の暗号・復号の自動検証は含んでおらず、起動と初期化を確認する『スモークテスト』として位置づけています」

→ F-IROH-33 の本質的な問題 (「実証した」と書かれているが実証していない) は、コードを変えずに**主張側を実態に合わせる**ことで解消。これは正当な解決方法。実テストの構造リファクタは Phase 3 へ持ち越し。

### F-IROH-26: dead code を Phase 3 用予約として明文化
> 「フィールド自体は将来の拡張性（フェーズ 3 のファイル転送等）のために維持し、現在は `sign_fp` による DSA 署名検証を MITM 防御の主軸としています」

→ コード上の dead code は残るが「意図的予約」であることが文書で明確化。意図不明問題は解消。

---

## △ 方向性転換 (注意事項あり)

### F-IROH-27 → F-IROH-34: explicit `close().await` パターンへの刷新
`src/network/iroh.rs:77-84, 118-147, 397-535`

```rust
let endpoint_cleanup = endpoint.clone();
let res = async {
    // ... 全処理 ...
}.await;
endpoint_cleanup.close().await;
res
```

`EndpointGuard` 構造体は完全削除済み。

**改善点**:

- ✅ 明示的なエラーパス (`?` で `Err` 伝搬) でも close が確実に実行される
- ✅ fire-and-forget でなく、close の完了を await できる
- ✅ ランタイム不在時の panic リスク解消

### F-IROH-34 🟡 (新規): 終了経路ごとの cleanup 確実性が変化

`async { ... }.await` の前後で cleanup を行うパターンは **task cancellation / timeout / panic に対しては cleanup が実行されない**:

| 終了パス | 旧 (Drop guard + spawn) | 新 (explicit close.await) |
|---|---|---|
| 正常 Ok | △ fire-and-forget | ✅ 確実に await |
| 明示的 Err 伝搬 | △ fire-and-forget | ✅ 確実に await |
| Panic | ✅ Drop が走り spawn | ❌ close.await に到達せず |
| `tokio::time::timeout` で cancel | ✅ Drop が走り spawn | ❌ 内側 await でサスペンド中に drop、close.await 未到達 |
| 親 task の `abort()` | ✅ Drop が走り spawn | ❌ 同上 |

**重要な観察**: 全 6 テストが `tokio::time::timeout(...)` で client/server を包んでいる。実装によっては timeout で内側 future が drop されるパスが頻出 → **テスト環境では旧版の方が cleanup 通過率は高かった可能性**。

ただし production の典型ワークロード (CLI で chat_mode=true、ユーザが Ctrl-C) では現行版も問題ない。実害は限定的だが、**「確実に終了することを保証しました」という remediation report の表現は cancel/panic パスを過大評価**している。

「正常系とエラー系で確実、cancel/panic はベストエフォート」が正確な記述。

---

## 引き継ぎ未対応 (Phase 3 へ)

| ID | 状態 |
|---|---|
| F-IROH-03 | ALPN ハードコード — 未対応 |
| F-IROH-08 | spawn_blocking 内シークレット寿命 — 未対応 |
| F-IROH-11 | 複数 ALPN — 未対応 |
| F-IROH-13 | `_s2c_iv` / `_c2s_iv` 未使用 — 未対応 |
| F-IROH-17 | NodeId rotation で cooldown 回避 — 未対応 |
| F-IROH-20 | `cfg!(test)` 混入 — 未対応 |
| F-IROH-21 | allowlist の role 非対称 — 未対応 |
| F-IROH-26 | `target_enc_fp` dead code — Phase 3 で活用予定として明文化 |
| F-IROH-28 | multi-client 認証 — Phase 3 |
| F-IROH-30 | chat_loop 真の E2E — Phase 3 |
| F-IROH-31 | relay メタデータ漏洩 / `--no-relay` — Phase 3 |

---

## 結論

**Phase 2 のクローズ条件は満たされた**と判断できる。

理由:

1. 主要修正 (F-IROH-29 / F-IROH-32 / F-IROH-26 / F-IROH-27) は完了またはスコープ明文化
2. F-IROH-33 (見かけ倒しテスト) は完了レポートの記述修正で実態と整合
3. 残存する技術的負債は全て Phase 3 のスコープに正しく接続されている

唯一の注釈は **F-IROH-34** (新規):

- explicit `close().await` への刷新は、cancel/panic 経路で旧版より弱くなる
- remediation report の「エラー発生時や早期 return 時も含め…確実に終了することを保証」は若干誇張
- 実用上の影響は小さく、Phase 3 で再評価可能

---

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体計画
- `PHASE1_*` — Phase 1 関連 (完了 / 修正サイクル / 検証サイクル)
- `PHASE2_COMPLETION_REPORT.md` — Phase 2 完了レポート
- `PHASE2_REMEDIATION_REPORT_FINAL.md` — Phase 2 修正完了 v2
- `PHASE2_REMEDIATION_REPORT_v3_FINAL.md` — Phase 2 修正完了 v3 (最終、本検証対象)
- `PHASE2_VERIFICATION_REPORT.md` — Phase 2 統合検証 v1
- `PHASE2_VERIFICATION_REPORT_v2.md` — Phase 2 検証 v2
