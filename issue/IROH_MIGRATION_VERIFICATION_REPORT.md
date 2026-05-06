# Iroh 移行プロジェクト 最終検証レポート (nkCryptoTool-rust)

作成日: 2026-05-06
対象:
- `IROH_MIGRATION_COMPLETION_REPORT.md` (全 4 フェーズ完了主張)
- `PHASE3_REMEDIATION_REPORT_FINAL.md` (Phase 3 最終修正主張)
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## エグゼクティブサマリ

**全 4 フェーズの計画した目標 (NAT 越え / Ticket / V3.1 ハンドシェイク / TCP deprecate) は達成**。Phase 3 残課題 (F-IROH-26 / F-IROH-34 / F-IROH-36) も今回の最終 remediation で完全対応。

**ただし F-IROH-39 を放置したまま「完了」宣言するのは時期尚早**。実機テスト (2026-05-06) で発見した致命的 bug が修正されておらず、production 配布で即座に発生する。修正は数行で済むが、検証用負例テストもセットで必要。

---

## 修正状況サマリ

| 指摘 | 修正主張 | 実コード |
|---|---|---|
| F-IROH-26 (target_enc_fp) | ✅ V3.1 で server KEM pub 交換 | ✅ **完全修正** (`iroh.rs:338, 363, 387, 522-548`) |
| F-IROH-36 (HKDF label) | ✅ "nk-auth-v3" | ✅ **完全修正** (line 371, 584) |
| F-IROH-34 (cleanup) | ✅ EndpointGuard + try_current() | ✅ **belt-and-suspenders 改善** (`iroh.rs:24-35`) |
| F-IROH-35 (file transfer test) | ✅ 命名改善 + アサーション | △ **assert 追加・命名 `_smoke` だが、`cfg!(test)` shortcut で本物の send/receive_file は依然未通過** |
| F-IROH-30 (chat_loop test) | ✅ smoke として明記 | ✅ **正直な命名に変更** (`test_iroh_chat_loop_smoke`) |
| Phase 4 (TCP deprecate) | ✅ 警告追加 / SPEC・README 更新 | ✅ **実装確認** (`main.rs:202`, SPEC.md `## 14`, README L38, 248) |
| **F-IROH-39 (実機 bug)** | ❌ **言及なし** | ❌ **未対応** (`mod.rs:420-426` で同じ無限ループコード) |

---

## ✅ 完了確認

### F-IROH-26 → V3.1 ハンドシェイクで完全解決
`iroh.rs:338-388` (server side):

```rust
let mut server_kem_pub = Vec::new();
// ... サーバ側で KEM private key からKEM public を導出 ...
server_kem_pub = raw_pub_kem;
CommonProcessor::update_transcript(&mut server_transcript, &server_kem_pub);
// ... transcript に含めて署名 ...
CommonProcessor::write_vec(&mut writer, &server_kem_pub).await?;
```

`iroh.rs:522-548` (client side):

```rust
let server_kem_pub = CommonProcessor::read_vec(&mut reader).await?;
CommonProcessor::update_transcript(&mut server_transcript, &server_kem_pub);
// ...
if let Some(expected_fp) = config.target_enc_fp {
    let actual_fp: [u8; 32] = Sha3_256::digest(&server_kem_pub).into();
    if actual_fp != expected_fp {
        return Err(...);
    }
}
```

ticket の `pqc_enc_fp` が初めて意味を持つ。MITM 検知の対象が DSA pubkey + KEM pubkey の **両方**に拡張。

### F-IROH-34 → 二重防御パターンに進化
`iroh.rs:24-35`:

```rust
pub struct EndpointGuard(pub Endpoint);
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let endpoint = self.0.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = endpoint.close().await;
            });
        }
    }
}
```

加えて `iroh.rs:451-452, 611` で explicit close.await も併用。Drop ベース (panic / cancel パスをカバー) と explicit close (success / error パスをカバー) の **両方**が動く設計。Phase 2 v3 で削除されたものが復活、双方の長所を採用。

### F-IROH-35 / F-IROH-30 → スコープ整合
- テスト名を `_e2e` → `_smoke` に変更 (line 847, 872) — **正直な命名**
- file_transfer_smoke にアサーション追加 (line 892: `assert!(client_res.unwrap().is_ok())`)

ただし **コードは依然 `cfg!(test)` shortcut** で抜けるため、`receive_file` / `send_file` の実コードは実行されず。命名と report 表記が実態に追いついた形。

### Phase 4 → 実装確認
- `main.rs:202`: TCP 使用時の deprecation 警告
- `SPEC.md` Section 14: Iroh / ALPN / V3 ハンドシェイク仕様
- `README.md` L38, 248-258: Iroh 使用例

---

## ❌ 致命的に未対応: F-IROH-39

`PHASE3_REMEDIATION_REPORT_FINAL.md` も `IROH_MIGRATION_COMPLETION_REPORT.md` も **F-IROH-39 に一切言及していない**。

実コード `mod.rs:420-426` を確認 — Phase 3 検証時と完全に同一:

```rust
res = Self::read_line_secure(&mut stdin, &mut line_buf) => {
    res?;
    if line_buf.is_empty() {
        let mut stdout = tokio::io::stdout();
        let _ = stdout.write_all(b"> ").await;
        let _ = stdout.flush().await;
        continue;  // ← stdin EOF でも continue → infinite loop
    }
```

`read_line_secure` の Ok(0) (= EOF) と Ok(0) (= 空行入力) を区別する仕組みがない。実機テスト (2026-05-06) で client.log が **2.5MB 超 (`> ` の連続)** を生成し実証済み。

→ **production で `Ctrl-D` を押した瞬間 / SSH 切断時 / パイプ完了時に CPU 100%**

---

## 🟡 完了レポートの誇張

migration completion の結論:
> 「『どこからでも、量子計算機に対しても安全に』通信できる強力な P2P 暗号ツールへと進化しました」

正確には:

- ✅ どこからでも (Iroh NAT 越え) — 動作
- ✅ 量子計算機に対しても安全 (PQC ハンドシェイク, V3.1 で MITM 検知も完全) — 動作
- ⚠️ **ただしユーザが Ctrl-D を押すと CPU を焼く** (F-IROH-39)

「完成」を宣言する前にこの 1 件は対処すべき。

---

## 引き継ぎ未対応 (継続)

| ID | 状態 |
|---|---|
| F-IROH-08 | spawn_blocking 内シークレット寿命 — 未対応 |
| F-IROH-11 | 複数 ALPN — Phase 3 で部分対応 (chat/file 2 種) |
| F-IROH-13 | `_s2c_iv` 未使用 — 未対応 |
| F-IROH-17 | NodeId rotation で cooldown 回避 — 未対応 |
| F-IROH-20 | `cfg!(test)` 混入 — Phase 4 でも残存 |
| F-IROH-21 | allowlist の role 非対称 — 未対応 |
| F-IROH-37 | file transfer 単方向 — migration 完了レポートで「今後の課題」明記、計画通り |
| **F-IROH-39** | **chat_loop EOF 無限ループ — 完了レポート言及なし、Critical 級未対応** 🔴 |

---

## 結論

**全 4 フェーズの計画した目標 (NAT 越え / Ticket / V3.1 ハンドシェイク / TCP deprecate) は達成**。Phase 3 残課題 (F-IROH-26 / F-IROH-34 / F-IROH-36) も今回の最終 remediation で完全対応。

**ただし F-IROH-39 を放置したまま「完了」宣言するのは時期尚早**。実機テストで発見した致命的 bug が修正されておらず、production 配布で即座に発生する。修正は数行で済むが、検証用負例テストもセットで必要。

**推奨**: 「完了」ステータスは保留し、F-IROH-39 修正 → 検証 → 真の完了の追加サイクルを 1 回挟むべき。

---

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体計画
- `IROH_MIGRATION_COMPLETION_REPORT.md` — 検証対象の全体完了レポート
- `PHASE1_*` — Phase 1 関連 (完了 / 修正 3 サイクル / 検証 3 サイクル)
- `PHASE2_*` — Phase 2 関連 (完了 / 修正 2 サイクル / 検証 3 サイクル)
- `PHASE3_*` — Phase 3 関連 (完了 / 修正 1 サイクル / 検証 1 サイクル)
