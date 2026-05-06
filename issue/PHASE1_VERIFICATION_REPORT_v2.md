# Phase 1 再検証レポート v2 (Iroh 移行) — nkCryptoTool-rust

作成日: 2026-05-06
対象: `PHASE1_COMPLETION_REPORT.md` (追記: セキュリティ修正) の修正主張に対する検証
前提: `PHASE1_VERIFICATION_REPORT.md` (v1) で指摘した F-IROH-01/04/05/06/10 への修正が入った旨の報告
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## エグゼクティブサマリ

修正主張のうち **コード上の構造変更は確認できる** が、**新規の重大欠陥が混入** している。特に **F-IROH-14 (channel binding 順序不一致) により、F-IROH-01 / F-IROH-10 の修正が構造上は存在するが認証経路は決して通らない**。再検証が `cargo check` 止まり (F-IROH-12 未対応) のため、このバグが検知されなかったと推定される。

> 「認証してるつもりで運用が始まる」状態は、認証なしで動く v1 状態より発見が遅れる分、危険度が高い。

---

## 修正状況サマリ

| 指摘 | コード変更 | 機能性 |
|---|---|---|
| F-IROH-01 (クライアント認証) | ✅ 実装 | ⚠️ **F-IROH-14 により非機能** |
| F-IROH-10 (サーバ認証) | ✅ 実装 | ⚠️ **F-IROH-14 により非機能** |
| F-IROH-06 (channel binding) | ✅ 実装 | ❌ **順序不一致バグ (F-IROH-14)** |
| F-IROH-04 (allowlist) | △ 部分修正 | ⚠️ allow_unauth で迂回可能 (F-IROH-16) |
| F-IROH-05 (セッションロック) | △ 順序改善 | ⚠️ **F-IROH-15 により永続リーク余地** |
| F-IROH-12 (Iroh テスト) | ❌ 未対応 | — |
| F-IROH-02/03/07/08/09/11/13 | ❌ 未対応 | — |

---

## 🔴 新規 Critical

### F-IROH-14: channel binding の順序不一致 (F-IROH-06 修正に混入)
**修正主張: F-IROH-06 解決 / 実態: 非機能で全認証失敗**

`src/network/iroh.rs:136-137` (server) vs `:307-308` (client)

```rust
// Server (handle_server_connection)
transcript.extend_from_slice(remote_node_id.as_bytes());  // = CLIENT_NodeId
transcript.extend_from_slice(local_node_id.as_bytes());   // = SERVER_NodeId
// → [CLIENT, SERVER]

// Client (run_connect)
transcript.extend_from_slice(remote_node_id.as_bytes());  // = SERVER_NodeId
transcript.extend_from_slice(local_node_id.as_bytes());   // = CLIENT_NodeId
// → [SERVER, CLIENT]
```

両者とも `(remote, local)` の順で extend しているが、**"remote" と "local" は視点で意味が反転**する。結果:

- Server transcript: `[CLIENT_NodeId][SERVER_NodeId][...]`
- Client transcript: `[SERVER_NodeId][CLIENT_NodeId][...]`

**この食い違いは transcript の冒頭で発生**するため、その後どれだけ同じデータを append しても永遠に一致しない。

帰結:
- **クライアントが署名した transcript ≠ サーバが検証する transcript** → `pqc_verify` 失敗 → 接続拒否
- 同じく **サーバ署名 ≠ クライアント検証 transcript** → サーバ認証も失敗
- → F-IROH-01 と F-IROH-10 の修正が **構造としては存在するが認証経路は決して通らない**

このバグが検知されていない事実は、**Iroh トランスポートで認証付き E2E 接続がテストされていない**ことを強く示唆 (F-IROH-12 が未解決のため整合)。`cargo check` では検出不能。

---

## 🟠 新規 High

### F-IROH-15: CHAT_ACTIVE の永続リーク (F-IROH-05 修正に混入)
**修正主張: F-IROH-05 解決 / 実態: 認証後フェーズで失敗すると永続 true**

`src/network/iroh.rs:197-205, 266-273`

```rust
// 197-205: handshake 内で CHAT_ACTIVE を true にセット
if std::sync::atomic::AtomicBool::compare_exchange(
    &CHAT_ACTIVE, false, true, ...
).is_err() { ... }

// ... 続いて line 208-262 で PQC encap, sig 生成, write 等

// 263: timeout block 終了 (`??` でエラー伝搬すると ChatActiveGuard 未生成)

// 266-273: ここで初めて ChatActiveGuard を作成
let _chat_guard = if config.chat_mode {
    Some(ChatActiveGuard { ... })
}
```

**CHAT_ACTIVE = true をセットしてから ChatActiveGuard を生成するまでに 60 行以上の失敗可能な処理**が挟まる:

- `pqc_encap` 失敗 (line 214)
- `SecureBuffer::new` 失敗 (line 220)
- `pqc_sign` 失敗 (line 241)
- `hkdf` 失敗 (line 246)
- `write_vec` / `write_all` 失敗 (line 255-260)

これらいずれかが失敗すると `??` でエラー伝搬 → `_chat_guard` は作られず → **CHAT_ACTIVE が true のまま誰も解除しない** → 以降のすべての chat 接続が "Chat session already active" で拒否される (= 単一クライアント DoS で永続無効化)。

TCP 版は guard を `compare_exchange` 直後に作成 (`src/network/tcp.rs` の対応箇所) して Drop パターンに任せていた。Iroh 版はこの不変条件を破った。

### F-IROH-16: allowlist は認証経路でのみ機能 (F-IROH-04 部分修正の穴)
**修正主張: F-IROH-04 解決 / 実態: allow_unauth=true で迂回可能**

`src/network/iroh.rs:167-172, 178-184`

```rust
if client_auth_flag[0] == 1 {
    // ... PQC sig 検証 ...
    if let Some(ref allowlist) = cached_allowlist {
        if !allowlist.contains(&hash) { return Err(...); }    // ← ここでしか照合しない
    }
} else if config.signing_pubkey.is_some() || !config.allow_unauth {
    return Err(CryptoError::Parameter("Handshake failed"...));
}

if peer_id_opt.is_none() {
    peer_id_opt = Some(PeerId::Node(*remote_node_id.as_bytes()));  // 認証無し時の fallback
}
```

問題:

1. **allowlist チェックは `client_auth_flag == 1` の中だけ**。`allow_unauth=true` で client_auth_flag=0 のピアは allowlist チェックを完全に経由しない。
2. allowlist は PQC 公開鍵ハッシュ (`PeerId::Pubkey`) で構成されているため、`PeerId::Node(NodeId)` の peer は構造的にも照合不能。
3. TCP 版 (`src/network/tcp.rs:204-229`) は `PeerId::Ip` でも allowlist チェックに入り、unauth peer を allowlist 有効時に拒否していた。Iroh 版にこの分岐がない。

帰結: `allow_unauth=true` + allowlist 設定の組み合わせで **allowlist が事実上無効**。

---

## 🟡 新規 Medium

### F-IROH-17: 認証無しピアの NodeId は cooldown を回避可能
`src/network/iroh.rs:183, 189-194`

```rust
peer_id_opt = Some(PeerId::Node(*remote_node_id.as_bytes()));  // ed25519 NodeId
// ... cooldown 照合は peer_id ベース
```

Iroh の NodeId は単なる ed25519 公開鍵で、**攻撃者は無コストで新規生成できる**。NodeId 単位の cooldown は事実上 cooldown 無し。TCP 版も IP 単位で似た脆弱性はあったが、Iroh では IP 制約すら無いので回避が更に容易。

### F-IROH-18: `nkct1` プレフィックスが装飾的
`src/network/iroh.rs:285`

```rust
let ticket = if ticket_str.starts_with("nkct1") { &ticket_str[5..] } else { ticket_str };
```

- プレフィックスがあっても無くても受け付ける → バージョン識別子として機能していない
- 不正プレフィックス (`nkct2...`) も `else` 経由で base32 デコード試行される → エラーメッセージが分かりにくい
- F-IROH-02 と整合: ticket フォーマットの厳格化が Phase 2 で必要

---

## 引き継ぎ (v1 から修正未対応で残置)

| ID | 項目 | 状態 |
|---|---|---|
| F-IROH-02 | ticket に PQC 指紋・checksum・version | Phase 2 予定通り未対応 |
| F-IROH-03 | ALPN ハードコード | 未対応 |
| F-IROH-07 | Endpoint cleanup | 未対応 |
| F-IROH-08 | spawn_blocking 内シークレット寿命 | 未対応 |
| F-IROH-09 | relay メタデータ | 未対応 |
| F-IROH-11 | 複数 ALPN 同時 accept | 未対応 |
| F-IROH-12 | **Iroh 単体テスト無し** | 未対応 (再検証 = `cargo check` のみ) |
| F-IROH-13 | `_s2c_iv` / `_c2s_iv` 未使用 | 未対応 |

---

## 確認できた修正項目 (positive findings)

| 項目 | 確認内容 |
|---|---|
| クライアント署名検証 | `iroh.rs:149-159` で `pqc_verify` 呼び出し追加 (機能性は F-IROH-14 で阻害) |
| `allow_unauth` チェック | `iroh.rs:174-180` で実装 |
| サーバ署名生成 | `iroh.rs:228-242` で `pqc_sign` 呼び出し追加 |
| サーバ署名検証 (クライアント側) | `iroh.rs:355-372` で実装 (機能性は F-IROH-14 で阻害) |
| channel binding (構造) | `iroh.rs:136-137, 307-308` で NodeId を transcript 先頭に追加 (順序バグあり) |
| allowlist プリロード | `iroh.rs:29-51` で `preload_allowlist` を追加し、認証時に hex 32B 指紋と照合 |
| セッションロック認証後化 | `iroh.rs:187-206` で auth 完了後に `compare_exchange` |
| `nkct1` プレフィックス導入 | `iroh.rs:77, 285` で形式上の version namespace を確保 (機能は F-IROH-18) |

---

## 重要な含意

**F-IROH-14 が示すのは、認証付き Iroh ハンドシェイクが一度も実成功していない可能性が高い**ということ。再検証が `cargo check` 止まりなのが直接の原因 (F-IROH-12 未対応の帰結)。

修正を入れたつもりが「認証は構造上存在するが現実には全例失敗」という最悪のケース — 完全に無効化されているより悪く、**「認証してるつもり」で運用が始まる**危険。

---

## 推奨優先順位

1. **F-IROH-14** — 即時。channel binding の canonical ordering を採用 (例: `(client_NodeId, server_NodeId)` を role に依らず固定順、または `min(a,b) || max(a,b)` でソート、ALPN・version も含めるとより堅牢)。
2. **F-IROH-12** — F-IROH-14 を発見するための前提条件。Iroh 上で auth 付き E2E テストを追加し、CI で常時実行。
3. **F-IROH-15** — guard 取得タイミングを `compare_exchange` 直後に戻す。
4. **F-IROH-16 / F-IROH-17** — allowlist セマンティクスの再設計。`allow_unauth=true` 時にも allowlist が利く分岐、および NodeId-only ピアの扱い (拒否 / 一時許可 / アプリ層で別チェック) を明文化。
5. **F-IROH-02 / F-IROH-18** — Phase 2 のスコープ通り、ticket フォーマットの厳格化と PQC 指紋 bundle で MITM 検知を本来の意図通りに動かす。

---

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体計画
- `PHASE1_COMPLETION_REPORT.md` — 検証対象の完了レポート (追記版)
- `PHASE1_VERIFICATION_REPORT.md` — v1 検証レポート (本ドキュメントの前提)
