# Phase 1 再検証レポート v3 (Iroh 移行) — nkCryptoTool-rust

作成日: 2026-05-06
対象: `PHASE1_REMEDIATION_REPORT.md` の修正主張に対する検証
前提:
- `PHASE1_VERIFICATION_REPORT.md` (v1)
- `PHASE1_VERIFICATION_REPORT_v2.md` (v2)
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## エグゼクティブサマリ

v2 で指摘した 3 件 (F-IROH-14 / F-IROH-15 / F-IROH-16) のうち、**F-IROH-14 と F-IROH-15 は完全修正、F-IROH-16 はデッドコードを伴う見かけの修正**。Iroh トランスポートの E2E テストが追加された (F-IROH-12 部分対応) ことで `cargo check` だけでは見えなかった機能性は大幅に確認可能になった。

ただし以下の問題が残存または新規発生:

- **F-IROH-22 (偽の "authenticated" ログ)** — 検証なしで認証成功と表示
- **F-IROH-16 のデッドコード** — 完了レポートの主張と実態が乖離
- **F-IROH-19 (ticket 形式の暗黙変更)** — `nkct1` プレフィックス消失、`iroh::NodeAddr` の JSON 直結
- **F-IROH-20 (`cfg!(test)` 混入)** — production コードで `todo!()` panic 経路
- 負例テストの欠如 — F-IROH-16 のデッドコードは負例テスト 1 件で検出可能だった

---

## 修正状況サマリ

| 指摘 | コード変更 | 機能性 |
|---|---|---|
| F-IROH-14 (channel binding 順序) | ✅ 実装 | ✅ **正しく機能** |
| F-IROH-15 (CHAT_ACTIVE リーク) | ✅ 実装 | ✅ **正しく機能** |
| F-IROH-16 (allowlist 統合) | ⚠️ 不完全 | ❌ **デッドコード経路** |
| F-IROH-12 (Iroh テスト) | △ 部分 | ⚠️ ハッピーパスのみ |

---

## ✅ 修正確認

### F-IROH-14: 修正完了
`src/network/iroh.rs:173-174` (server) / `:355-356` (client)

```rust
// Server
transcript.extend_from_slice(remote_node_id.as_bytes()); // = Client
transcript.extend_from_slice(local_node_id.as_bytes());  // = Server

// Client
transcript.extend_from_slice(local_node_id.as_bytes());  // = Client
transcript.extend_from_slice(remote_node_id.as_bytes()); // = Server
```

両者とも `[CLIENT_NodeId, SERVER_NodeId]` で一致。コメント `// Client` / `// Server` も誤解を防いでいる。`test_iroh_handshake_auth_success` がこのパスを通って成功している事実が機能性を裏付ける。

### F-IROH-15: 修正完了
`src/network/iroh.rs:290-317`

`compare_exchange` で `CHAT_ACTIVE = true` をセットした直後に `Some(ChatActiveGuard{...})` を生成。間に失敗可能処理は無し。失敗可能処理 (PQC encap, sign, write 等) はすべて handshake_result の生成までに完了し、guard 生成より前のフェーズに移動した。RAII で確実に解放される。

---

## ⚠️ 不完全修正

### F-IROH-16 🟠: 部分修正、デッドコード混入
`src/network/iroh.rs:217-230`

```rust
if let Some(ref allowlist) = cached_allowlist {
    match peer_id {
        PeerId::Pubkey(hash) => {
            if !allowlist.contains(&hash) { return Err(...); }
        }
        _ => {
            if !config.allow_unauth {  // ← デッドコード
                 return Err(...);
            }
        }
    }
}
```

問題: `_` アーム (= 匿名ピア = `PeerId::Node`) に到達するのは `client_auth_flag == 0 && allow_unauth == true` のケースのみ (line 207-208 で `!allow_unauth` の場合は既に弾かれているため)。よって **`!config.allow_unauth` は常に `false`** で、このブランチは **匿名ピアを素通りさせるだけのデッドコード**。

実際の挙動: allowlist 設定 + `allow_unauth=true` では匿名ピアが allowlist チェックを完全に経由しない。完了レポートの「適切な権限のないピアからの接続は…拒否されます」は実コード上で**偽**。

このデッドコードは負例テスト (allowlist 設定 + 未登録ピア接続 → 拒否) を 1 件追加していれば即座に検出できた。F-IROH-12 の不完全さと因果関係がある。

---

## 🆕 新規発見

### F-IROH-19 🟡: ticket フォーマットが無告知で JSON 化
`src/network/iroh.rs:97, 335`

```rust
let ticket = serde_json::to_string(&node_addr)?;  // listen 側
let node_addr: NodeAddr = serde_json::from_str(ticket_str)?;  // connect 側
```

修正前は `nkct1<base32(NodeId)>` だったが、**`iroh::NodeAddr` の JSON シリアライズ**に置換されている。問題:

- `nkct1` プレフィックス消失 → version namespace 不在
- `data-encoding` 依存が事実上無用に (`Cargo.toml` に残置)
- **wire format が iroh の内部構造体に直結** → iroh のメジャーアップグレードで ticket 互換が破れる
- F-IROH-02 (PQC 指紋 bundle) の解決余地が後退 (`NodeAddr` を拡張するには serde で wrapper が必要)
- README / SPEC 未更新と推定 (要確認)
- IROH_MIGRATION_PLAN.md の ticket 仕様 (BASE32 + チェックサム + バージョン + PQC 指紋 bundle) と完全に乖離

### F-IROH-20 🟡: `cfg!(test)` 分岐が production コードに混入
`src/network/iroh.rs:321-325, 341, 468-470`

```rust
} else if cfg!(test) {
    writer.shutdown().await...?;
    return Ok(());
} else {
    todo!("File transfer over Iroh")
}
```

`cfg!(test)` は**コンパイル時定数**。挙動:

- このクレート内の `#[test]` 関数: `cfg!(test) == true` ✓
- このクレートを依存とする他クレートのテスト: `cfg!(test) == false` → `todo!()` で panic
- `tests/` ディレクトリの integration test: 同上 panic 経路
- **release build で `chat_mode=false` のパスを通すと panic**

`#[cfg(test)]` で関数を分離するか、別の boolean フラグで制御するのが本来。production コードに `cfg!(test)` を混ぜるのはコードスメル。

### F-IROH-21 🟡: allowlist が role 非対称で同一集合
`src/network/iroh.rs:217-230` (server) / `:416-424` (client)

`preload_allowlist` は listen / connect 両方で同じファイルから同じ HashSet を構築。Server は「許可されたクライアント」、Client は「許可されたサーバ」を確認したいが、**両者を同じ集合で扱う**設計。

帰結: トラステッドサーバ S の指紋を allowlist に入れた利用者 A は、A が listen している時に **S からの incoming 接続も自動で受け入れる**。意図と乖離。

### F-IROH-22 🟠: `signing_pubkey=None` + `allow_unauth=true` で偽の認証成功ログ
`src/network/iroh.rs:186-206`

```rust
if client_auth_flag[0] == 1 {
    let sig = CommonProcessor::read_vec(&mut reader).await?;  // 読むだけ
    if let Some(ref pubkey_path) = config.signing_pubkey {
        // ... pqc_verify ...
    } else if !config.allow_unauth {
        return Err(...);
    }
    eprintln!("Client authenticated successfully.");  // ← 検証無しでもここに到達
}
```

`client_auth_flag=1` で送られてきた署名を、`signing_pubkey` 未設定 + `allow_unauth=true` のとき **`pqc_verify` を呼ばずに「認証成功」と表示**。peer_id は `PeerId::Node(NodeId)` のまま (匿名扱い)。

実害: 運用ログで「authenticated」と表示されるが実態は匿名接続。インシデント解析の混乱。

### F-IROH-23 🟡: server は単一クライアントしか認証できない
`src/network/iroh.rs:188-202`

`signing_pubkey` は単一ファイルパスで単一公開鍵を表す。複数のクライアントを認証しつつ受け入れるには allowlist が必要だが、F-IROH-22 と組み合わさり、`signing_pubkey=None` + allowlist だけでは「authenticated」フラグが立たないため peer_id は Node のまま → allowlist の Pubkey アームに到達せず素通り。

実質的に **「multi-client authenticated server」が現状の API では構成不可能**。TCP 版から継承した設計上の制約だが、P2P モデルでは顕在化しやすい。

### F-IROH-25 🟡: `endpoint.close()` が早期 return で skip される
`src/network/iroh.rs:466-475`

```rust
let res = if ... {
    chat_loop(...).await
} else if cfg!(test) {
    writer.shutdown().await...?;  // ← `?` で早期 return すると endpoint.close() されない
    Ok(())
} else { todo!(...) };
endpoint.close().await;
res
```

`writer.shutdown()` が失敗すると `?` で関数を抜け、`endpoint.close().await` が実行されない → relay 接続や hole-punch session のリソースリーク。Drop ガードパターンに置き換えるべき。

`start()` (line 100-102) も同様に `run_listen_loop` がパニックすると close されない。

---

## 📋 テストカバレッジの問題 (F-IROH-12 部分対応の限界)

完了レポートで「Iroh トランスポートの E2E テスト追加」とあるが、**ハッピーパスのみ**:

| 観点 | カバー |
|---|---|
| 認証成功 | ✅ `test_iroh_handshake_auth_success` |
| 未認証許可成功 | ✅ `test_iroh_handshake_unauth` |
| 不正署名拒否 | ❌ 無し |
| サーバ不一致拒否 | ❌ 無し |
| allowlist 不在ピア拒否 | ❌ 無し |
| F-IROH-14 リグレッション | ❌ 無し (順序検証が無いと再発見できない) |
| F-IROH-15 (CHAT_ACTIVE リーク) | ❌ 無し |
| F-IROH-16 (デッドコード) | ❌ 無し (テストで早く検出されたはず) |
| 実 chat_loop 動作 | ❌ `chat_mode=false` で `cfg!(test)` 経路、本物の chat_loop 未実行 |
| cooldown 動作 | ❌ 無し |
| 並列接続 / Semaphore 制限 | ❌ 無し |

特に **F-IROH-16 のデッドコード問題は、allowlist 拒否の負例テストが 1 つでもあれば即座に検出された**。テスト戦略の見直しが必要。

---

## 引き継ぎ (未対応のまま継続)

| ID | 状態 |
|---|---|
| F-IROH-02 | Phase 2 予定通り (ただし F-IROH-19 で実装方針が乖離) |
| F-IROH-03 (ALPN ハードコード) | 未対応 |
| F-IROH-07 (Endpoint cleanup) | 部分対応 (`close` 呼び出し追加) だが F-IROH-25 で弱い |
| F-IROH-08 (spawn_blocking 内シークレット寿命) | 未対応 |
| F-IROH-09 (relay メタデータ) | テスト時 `RelayMode::Disabled`、production は `Default` のまま |
| F-IROH-11 (複数 ALPN) | 未対応 |
| F-IROH-13 (`_s2c_iv` / `_c2s_iv`) | 未対応 |
| F-IROH-17 (NodeId 単位 cooldown は回避可能) | 未対応 |
| F-IROH-18 (`nkct1` プレフィックス装飾的) | F-IROH-19 で moot 化 (別問題に置換) |

---

## 優先度サマリ

1. **F-IROH-22** 🟠 (偽の "authenticated" ログ) — 運用上の認知ミスを誘発、即時対処
2. **F-IROH-16 デッドコード** 🟠 (allowlist 不完全) — 完了レポートの主張と実態の乖離、即時対処
3. **F-IROH-19** 🟡 (ticket 形式の暗黙変更) — Phase 2 で再設計予定なら方針確認、`IROH_MIGRATION_PLAN.md` との整合
4. **F-IROH-20** 🟡 (`cfg!(test)` 混入) — Phase 2 でファイル転送実装時に同時整理
5. **F-IROH-12 拡充** — 負例テスト追加が必須、F-IROH-16 のような問題を防ぐ
6. **F-IROH-21 / F-IROH-23** — P2P モデルでの allowlist セマンティクス再設計
7. **F-IROH-25** — `endpoint.close()` の Drop ガード化

---

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体計画。F-IROH-19 で ticket 仕様が乖離。
- `PHASE1_COMPLETION_REPORT.md` — 修正追記版。
- `PHASE1_REMEDIATION_REPORT.md` — 検証対象の修正完了レポート。
- `PHASE1_VERIFICATION_REPORT.md` — v1 検証 (Critical 2 / High 3 / Medium 5 / Low 3)。
- `PHASE1_VERIFICATION_REPORT_v2.md` — v2 検証 (新規 Critical 1 / 新規 High 2 / 新規 Medium 2)。
