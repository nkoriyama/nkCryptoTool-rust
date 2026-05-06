# Phase 3 検証レポート (Iroh 移行) — nkCryptoTool-rust

作成日: 2026-05-06
対象: `PHASE3_COMPLETION_REPORT.md` の修正主張に対する検証
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## エグゼクティブサマリ

**Phase 3 の本質的成果**: F-IROH-28 (multi-client 認証) は重要な改善で V3 ハンドシェイクとして実装済み。F-IROH-03 / F-IROH-31 / F-IROH-09 は計画通り完了。

**問題点**:

- 完了レポートに **F-IROH-26 と F-IROH-34 が誤って "対応済み" として列挙**されている (実態は未対応)
- **F-IROH-35 (新規)**: `test_iroh_file_transfer_e2e` がアサーション無し、かつ `cfg!(test)` ショートカットで実際のファイル転送コードを通っていない
- 完了レポートの「E2E テストにより正常な送受信を検証済み」は事実に反する
- **F-IROH-39 (新規・実機テストで発見)**: stdin EOF で `chat_loop` が無限 tight loop に陥る。CPU 100% + stdout 洪水。実機テストで client.log が 2.5MB 超に膨張して実証

これらを総合すると **Phase 3 を「全実装フェーズ完了」と宣言するには時期尚早**。

---

## 実機動作テスト結果 (2026-05-06)

LAN 内で listener / connector を別プロセスで実行し、ハンドシェイク完了 → メッセージ往復までを検証。

### ✅ 確認できた動作

```
=== client.log ===
[nkct] Connecting to NodeId: 936df7a46ee11528...
Server authenticated successfully.
--- Chat mode started ---

=== server.log ===
Client authenticated successfully.
--- Chat mode started ---
[Peer]: Hello from client     ← クライアントが暗号化送信した文字列がサーバ側で復号成功
```

実証されたこと:

1. ✅ Iroh トランスポートで V3 PQC ハンドシェイク完了 (双方向 ML-DSA-65 認証)
2. ✅ ticket (`nkct1AGJW355EN3QRKKFZYU7OTLYO3U4...`) の生成・パース・接続
3. ✅ AEAD (AES-256-GCM) 暗号化・復号が QUIC ストリーム上で動作
4. ✅ framing / nonce 管理が動作
5. ✅ `--no-relay` オプション動作
6. ✅ NodeId ベース接続 (LAN 内)

→ **「Iroh によるチャットは実行可能」を実機で確認**。

### 🔴 同時に発見した致命的バグ → F-IROH-39 として記載

---

## 修正状況サマリ

| 指摘 | 修正主張 | 実コード |
|---|---|---|
| F-IROH-03 (ALPN 分離) | ✅ 実装 | ✅ **完全実装** |
| F-IROH-28 (multi-client) | ✅ V3 ハンドシェイク | ✅ **完全実装** |
| F-IROH-31 / F-IROH-09 (relay) | ✅ `--no-relay` / `--relay-url` | ✅ **完全実装** |
| ファイル転送実装 | ✅ Iroh 上に移植 | △ **production コードのみ、テスト未通過** (F-IROH-35) |
| F-IROH-26 (target_enc_fp) | ✅ V3 で対応と記載 | ❌ **未対応** (sign_fp のみ照合、enc_fp は依然 dead code) |
| F-IROH-34 (cleanup) | ✅ 刷新と記載 | ❌ **コード変更なし** (v3 final と同一、cancel/panic 弱点継続) |

---

## ✅ 正しく完了した修正

### F-IROH-03: ALPN 分離
`mod.rs:20-21`, `iroh.rs:91, 177-193, 441`

```rust
pub const ALPN_CHAT: &[u8] = b"nkct/chat/1";
pub const ALPN_FILE: &[u8] = b"nkct/file/1";
```

サーバは両 ALPN を register し、`connecting.alpn().await` で着信時に判別 → `config.chat_mode` を上書き。クライアントは `chat_mode` から ALPN を選択。設計通り。

### F-IROH-28: V3 ハンドシェイクで multi-client 認証
`iroh.rs:268-297` (server), `iroh.rs:479-495` (client)

```rust
// V3: Receive Client's PQC DSA Public Key
let client_dsa_pub = CommonProcessor::read_vec(&mut reader).await?;
CommonProcessor::update_transcript(&mut transcript, &client_dsa_pub);

let sig = CommonProcessor::read_vec(&mut reader).await?;

if let Some(ref pubkey_path) = config.signing_pubkey {
    // pinned key check
}

if !backend::pqc_verify(&config.pqc_dsa_algo, &client_dsa_pub, &transcript, &sig)? {
    return Err(CryptoError::SignatureVerification);
}

let hash: [u8; 32] = Sha3_256::digest(&client_dsa_pub).into();
peer_id_opt = Some(PeerId::Pubkey(hash));
```

クライアントの DSA 公開鍵を受信 → 署名検証 → 指紋を peer_id に。これで `signing_pubkey=None` + allowlist で複数の認証済みクライアントを受け入れ可能。

`test_iroh_handshake_multi_client_auth_success` (line 965-1021) で実機検証済み。Critical 修正で品質高い。

### F-IROH-31 / F-IROH-09: relay 設定
`iroh.rs:89-107`, `config.rs:116-117`, `main.rs:111-114`

```rust
async fn create_endpoint(&self, is_test: bool) -> Result<Endpoint> {
    let mut builder = Endpoint::builder().alpns(vec![ALPN_CHAT.to_vec(), ALPN_FILE.to_vec()]);

    if is_test || self.config.no_relay {
        builder = builder.relay_mode(iroh::RelayMode::Disabled);
    } else if let Some(ref url) = self.config.relay_url {
        let relay_url = iroh::RelayUrl::from_str(url)?;
        builder = builder.relay_mode(iroh::RelayMode::Custom(...));
    }
    builder.bind().await
}
```

`--no-relay` (direct only)、`--relay-url <url>` (private relay) 共に実装。デフォルトは Iroh 公式 relay (要文書化)。

---

## ❌ 修正主張と実態の乖離

### F-IROH-26: 「V3 ハンドシェイクで対応」と記載されているが未対応
完了レポート:
> 「3.2 V3 ハンドシェイクの実装 (F-IROH-28, **F-IROH-26**)」

実コードの V3 ハンドシェイクで送受信されるのは **DSA 公開鍵のみ**。**KEM 公開鍵 (encryption pubkey) は依然サーバから送信されない**ため、`target_enc_fp` の照合パスは存在しない。

```rust
// run_connect line 436-438
if ticket.pqc_fp_algo & 2 != 0 {
    config.target_enc_fp = Some(ticket.pqc_enc_fp);  // 設定するが…
}
// 以降、target_enc_fp を照合するコードは皆無
```

V3 ハンドシェイクが解決したのは F-IROH-28 のみ。F-IROH-26 (`target_enc_fp` の dead code) は **未対応のまま**。完了レポートの記述は誤解を招く。

### F-IROH-34: 「刷新」と記載されているが v3 final から変更なし
完了レポート:
> 「5. リソース管理の確実化 (F-IROH-34): `async` ブロックと明示的な `close().await` 待機を組み合わせたクリーンアップパターンに刷新しました。これにより、タイムアウトやエラー発生時もバックグラウンドタスクが残留せず、確実に終了します」

実コード (`iroh.rs:73-80, 129-159, 443-602`) は **Phase 2 v3 final と完全に同一**。Phase 2 v3 検証で指摘した「`tokio::time::timeout` で cancel された場合 close.await が実行されない」問題は **依然として残存**。

| 終了パス | 実態 (v3 final と同じ) |
|---|---|
| 正常 Ok / 明示的 Err | ✅ close.await 実行 |
| Panic / timeout cancel / abort | ❌ close.await 未到達 |

完了レポートの「タイムアウトやエラー発生時も…確実に終了」は cancel パスを過大評価している。**実質的に新たな修正は入っていない**。

---

## 🟠 新規 F-IROH-35: `test_iroh_file_transfer_e2e` がアサーション無し
`iroh.rs:928-961`

```rust
#[tokio::test]
#[serial]
async fn test_iroh_file_transfer_e2e() {
    reset_state();
    // ... setup with chat_mode = false ...

    let client_res = tokio::time::timeout(Duration::from_secs(2), async {
        let processor = NetworkProcessor::new(client_config);
        processor.run_connect().await
    }).await;

    server_task.abort();
    println!("File transfer test result: {:?}", client_res);  // ← アサーション無し
}
```

問題:

1. **アサーション完全欠落**: `assert!` も `match` も無く、`println!` で結果を表示するだけ。**結果が `Err` でも panic でも PASS する**
2. **そもそもファイル転送が走らない**: `chat_mode=false` + `cfg!(test)=true` で `writer.shutdown(); Ok(())` のショートカットを通る (line 590-591, 414-416)。`send_file` / `receive_file` は **一度も呼ばれない**
3. テスト名と実際の検証内容の乖離

完了レポートの主張:
> 「TCP 版のロジックを汎用化し、Iroh の双方向ストリーム上で量子耐性のあるファイル送受信を実現しました。**E2E テストにより正常な送受信を検証済みです**」

実態とは完全に乖離している。**production コードに `send_file` / `receive_file` の呼び出しは存在する**が、それが正しく動くか **テストでは一度も実行されていない**。F-IROH-33 (chat_loop テスト) と同型の見かけ倒し。

---

## 🔴 新規 Critical: F-IROH-39 — stdin EOF で `chat_loop` が無限 tight loop
`src/network/mod.rs:280-339` (chat_loop の tx 経路)

```rust
res = Self::read_line_secure(&mut stdin, &mut line_buf) => {
    res?;
    if line_buf.is_empty() {
        let mut stdout = tokio::io::stdout();
        let _ = stdout.write_all(b"> ").await;
        let _ = stdout.flush().await;
        continue;  // ← stdin EOF だと即再 read → 即 EOF → 無限ループ
    }
    // ...
}
```

`read_line_secure` (`mod.rs:71-96`) は EOF で `Ok(total)` を返す (total=0 もあり得る)。`line_buf.is_empty()` で `continue` → 次反復で再度 EOF → 無限の tight loop。

### 実証データ

実機テストで:

- クライアント側 client.log が **2.5MB 超** (`> ` の連続)
- 同様に server 側でも、stdin 用 FIFO の writer が閉じた瞬間から同症状
- CPU 100% + stdout 洪水

### 影響範囲

- **TCP / Iroh 両方の `chat_loop` に影響** (汎用関数のため)
- 既存テストで未検出 — `test_iroh_chat_loop_e2e` は timeout で抜けるため EOF パスを通らない
- production で **Ctrl-D / SSH 切断 / `cmd | nkct ...` パイプ完了** 等で stdin が閉じた瞬間に発症
- F-IROH-30 (chat_loop の本格テスト不在) が示唆していた未検知バグの典型例

### 重要度

🔴 **Critical**。production デプロイ後にユーザが Ctrl-D した瞬間 CPU を焼く。修正自体は EOF 検出して chat_loop を抜けるだけで簡単だが、**修正検証のために負例テストが必須** (今までの test がこれを見逃したため、同種の見逃しを再発させない)。

---

## 🟢 新規 観察事項

### F-IROH-36: HKDF salt label が "nk-auth-v2" のまま
`iroh.rs:361, 573`

```rust
let okm = backend::hkdf(&combined_ss, 88, &salt, "nk-auth-v2", "SHA3-256")?;
```

V3 ハンドシェイクに移行したが label は `"nk-auth-v2"` のまま。動作上は問題ないが、将来 V4 等で更新する際に整合性確認が必要になる cosmetic な debt。

### F-IROH-37: ファイル転送が単方向 (client→server のみ)
`iroh.rs:419, 594`

両側とも `c2s_key` / `c2s_iv` を使用 → ファイルは常にクライアントが送信、サーバが受信。サーバから送出するパスは存在しない。設計判断だが文書化が必要。

加えて入出力が `tokio::io::stdin()` / `tokio::io::stdout()` のみで、**ファイルパス指定での転送はサポートされていない**。Unix pipe 用途専用に近い。

---

## 引き継ぎ未対応 (Phase 4 へ?)

| ID | 状態 |
|---|---|
| F-IROH-08 | spawn_blocking 内シークレット寿命 — 未対応 |
| F-IROH-11 | 複数 ALPN 同時 accept (Phase 3 で部分対応 — chat/file 2 種) |
| F-IROH-13 | `_s2c_iv` / `_c2s_iv` 未使用 — F-IROH-37 でファイル転送に活用、ただし `_s2c_iv` は依然未使用 |
| F-IROH-17 | NodeId rotation で cooldown 回避 — 未対応 |
| F-IROH-20 | `cfg!(test)` 混入 — Phase 3 でファイル転送実装するも `cfg!(test)` shortcut 残存 |
| F-IROH-21 | allowlist の role 非対称 — 未対応 |
| F-IROH-26 | target_enc_fp dead code — Phase 3 で対応と主張するも実態は未対応 |
| F-IROH-34 | cleanup の cancel パス — 主張のみ、実装変更なし |
| F-IROH-35 | file transfer test 見かけ倒し — 新規 |
| **F-IROH-39** | **chat_loop の stdin EOF 無限ループ — 実機テストで発見** 🔴 |

---

## 総合評価

**Phase 3 の本質的成果**: F-IROH-28 (multi-client 認証) は重要な改善。F-IROH-03 / F-IROH-31 / F-IROH-09 は計画通り完了。

**問題点**: 完了レポートに **F-IROH-26 と F-IROH-34 が誤って "対応済み" として列挙**されている。さらに **F-IROH-35 (test_iroh_file_transfer_e2e がアサーション無し)** が新規発生。実機テストで **F-IROH-39 (chat_loop の stdin EOF 無限ループ)** が発見された。これらを総合すると Phase 3 を「全実装フェーズ完了」と宣言するには時期尚早。

最低限、以下の対処が必要:

1. **F-IROH-39 を最優先で修正** (production で CPU 100% を引き起こす致命的 bug)
2. F-IROH-35 に実アサーションとファイル転送の往復検証を追加
3. F-IROH-26 / F-IROH-34 の対応状況を完了レポートで正確に再記述 (未対応として明示するか、本当に対応する)

---

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体計画
- `PHASE1_*` — Phase 1 関連 (完了 / 修正 3 サイクル / 検証 3 サイクル)
- `PHASE2_*` — Phase 2 関連 (完了 / 修正 2 サイクル / 検証 3 サイクル)
- `PHASE3_COMPLETION_REPORT.md` — 検証対象の Phase 3 完了レポート
