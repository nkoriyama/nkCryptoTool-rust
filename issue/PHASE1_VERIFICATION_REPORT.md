# Phase 1 検証レポート (Iroh 移行) — nkCryptoTool-rust

作成日: 2026-05-06
対象: `PHASE1_COMPLETION_REPORT.md` の完了主張に対する検証
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## 検証サマリ

完了レポートで主張されているモジュール再構成・依存追加・CLI 拡張・PQC ハンドシェイク移植は**実コード上で確認できる**。一方で、**TCP 版 (`src/network/tcp.rs`) に存在していたセキュリティ層が Iroh 版 (`src/network/iroh.rs`) で複数欠落**している。デフォルトトランスポートが Iroh のため、現状のままだと**認証なしで誰でも E2E チャット接続が成立する**状態。

| レポート記載 | 実態 |
|---|---|
| 「PQC ハンドシェイクを移植」 | 鍵交換は移植済み。**認証 (署名検証) は移植されていない** |
| 「Iroh の TLS 1.3 の上に PQC 層を重ねる二重構造を維持」 | 構造は維持されているが、**両層の channel binding がない**ため二重構造の意義が弱い (F-IROH-06) |
| 「単体テストが全て pass」 | TCP 版テストのみ。**Iroh 版テストはゼロ** (F-IROH-12) |
| 「`--listen`: NodeId を表示し、接続用 Ticket を出力」 | NodeId をそのまま BASE32 にしただけで Ticket と呼ぶには情報不足 (F-IROH-02) |

---

## 🔴 Critical

### F-IROH-01: クライアント認証が完全に無効化されている
`src/network/iroh.rs:120-126`

```rust
if client_auth_flag[0] == 1 {
    let _sig = CommonProcessor::read_vec(&mut reader).await?;  // 読み捨て、検証無し
}
```

TCP 版 (`src/network/tcp.rs:155-191`) では `pqc_verify` で署名検証 → `PeerId::Pubkey(hash)` で長期鍵指紋を peer ID にしていた。Iroh 版では:

1. 署名を読むが **`pqc_verify` を呼んでいない**
2. `config.allow_unauth` チェックが**ない** (`tcp.rs:186-194` 相当が欠落)
3. `config.signing_pubkey` の検証パスが**ない**
4. クライアント側 (`iroh.rs:216`) は **常に `client_auth_flag = [0u8]`** を送るので、署名提示の経路自体が無い

→ デフォルトトランスポート (Iroh) で **誰でも認証なしに接続可能**。

### F-IROH-10: サーバ認証も無効化
`src/network/iroh.rs:148, 230-232`

```rust
let server_auth_flag = [0u8];  // 常に 0
...
if server_auth_flag[0] == 1 {
    let _sig = CommonProcessor::read_vec(&mut reader).await?;  // 検証なし
}
```

クライアントはサーバが正しい長期鍵を持っているか検証する手段がない。**双方向で身元検証が消えている**。

---

## 🟠 High

### F-IROH-04: `peer_allowlist` が Iroh モードで機能不全
`src/network/iroh.rs:77-78`

```rust
let peer_id_bytes = connection.remote_node_id().map(|id| *id.as_bytes()).unwrap_or([0u8; 32]);
let peer_id = PeerId::Node(peer_id_bytes);
```

- `peer_allowlist` は `PeerId::Pubkey(SHA3-256(ML-DSA pubkey))` で照合する設計。
- Iroh 版は `PeerId::Node(ed25519 NodeId)` を生成 → **鍵空間が異なる別物**で照合不能。
- 加えて TCP 版の allowlist 適用ロジック (`tcp.rs:204-229` 相当) が Iroh 版から完全欠落。

→ allowlist を設定しても Iroh モードでは効かない。

### F-IROH-05: セッションロックの peer_id がゼロ埋めにフォールバック
`src/network/iroh.rs:77, 99-105`

```rust
let peer_id_bytes = connection.remote_node_id().map(...).unwrap_or([0u8; 32]);
...
if CHAT_ACTIVE.swap(true, ...) { return Err(...) }  // handshake 前に取得
Some(ChatActiveGuard { peer_id: peer_id.clone(), ... })
```

2 つの問題:

1. `remote_node_id()` 失敗時に `[0u8; 32]` を peer_id に → **全 unknown peer が同一視**され、cooldown も全員集合に対して 1 つだけ記録される。
2. TCP 版は handshake **完了後**に `compare_exchange` で取得 (`tcp.rs:239-251`)。Iroh 版は handshake **前**に取得 → 失敗パスも全部スロットを掴む。

### F-IROH-06: PQC ハンドシェイクと Iroh 層に channel binding がない
`src/network/iroh.rs:117-118, 213-214`

transcript は `client_ecc_pub || client_kem_pub || client_auth_flag || server_ecc_pub || kem_ct || server_auth_flag` のみ。**Iroh の NodeId / ALPN / connection 識別子が transcript に入っていない**。

二層構造の意義は "古典が破れても PQC が残る" だが、**両層を束ねる束縛が無い**ため以下の攻撃シナリオが成立しうる:

- 攻撃者 M が NodeId_M で A の接続を引き取り
- M は A から受けた PQC ハンドシェイクを別の被害者 V に転送
- A の transcript と V の transcript が NodeId 非依存なので **両方とも有効として確立可能**
- A は「B と話している」と思いつつ M 経由で V と E2E が成立する余地

→ 古典 TLS が破れた前提では PQC 層単独でも MITM 不可能であるべきだが、現状そうなっていない。

---

## 🟡 Medium

### F-IROH-02: ticket に PQC 公開鍵指紋・チェックサム・バージョン無し
`src/network/iroh.rs:50-51, 181-182`

```rust
let ticket = BASE32_NOPAD.encode(node_id.as_bytes());
```

- NodeId 32B のみ。Phase 2 で実装予定の PQC 指紋 bundle が**未実装**のため、F-IROH-01 / F-IROH-10 と組み合わさり MITM 完全フリー。
- チェックサム無し → タイプミスで別 NodeId にデコードしうる
- バージョンプレフィックス無し → フォーマット拡張時に区別不能

### F-IROH-12: Iroh 版の単体テストが存在しない
`src/network/iroh.rs` 全 273 行に `#[tokio::test]` ゼロ。完了レポートの「単体テスト pass」は **TCP 版テストの pass** のみ。Iroh トランスポートでの handshake / chat / cooldown / replay 検知のいずれも E2E 検証されていない可能性が高い。

### F-IROH-03: ALPN `nkct/chat/1` のハードコード
`src/network/iroh.rs:39, 184`

ファイル転送 (`todo!()` 状態) も同じ ALPN で受け入れる前提になっており、将来 `nkct/file/1` を分離する余地を最初から潰している。`chat_mode` flag をペイロード中で見るのではなく ALPN レベルで分離するのが本来の Iroh 流儀。

### F-IROH-07: Endpoint の終了処理なし
`src/network/iroh.rs:38-86`

accept ループに break パスなし、`Endpoint::close()` 呼び出しなし。Ctrl-C 時に relay 接続や hole-punch session が中途半端に残る可能性。

### F-IROH-11: ALPN バージョニング非対応
`src/network/iroh.rs:39`

`Endpoint::builder().alpns(vec![alpn.to_vec()])` で 1 ALPN のみ登録。複数バージョン同時 accept に未対応。

---

## 🟢 Low / 引き継ぎ事項

### F-IROH-08: `spawn_blocking` 内で clone されたシークレットの寿命
`src/network/iroh.rs:131-138, 234-246`

`Zeroizing<Vec<u8>>` を clone してから move。blocking task キャンセル時の zeroize タイミングが await 境界に依存。TCP 版でも同じ構造のため新規欠陥ではないが Iroh 版にも継承。

### F-IROH-09: relay 経由のメタデータ
`src/network/iroh.rs:38-44`

`Endpoint::builder()` で relay 設定をデフォルトのまま使用。`--no-relay` / 自前 relay 指定のオプションは未実装 (Phase 3 マターと整合)。

### F-IROH-13: `_s2c_iv` / `_c2s_iv` 派生だけして未使用
`src/network/iroh.rs:111, 196`

ハンドシェイクで IV を 88B HKDF から切り出すが捨てている。`chat_loop` は自前 nonce を生成するため不要だが、設計意図が読み取りにくい。TCP 版でも同じ。

---

## 検証で確認できた事項 (positive findings)

| 項目 | 確認内容 |
|---|---|
| モジュール再構成 | `src/network/{mod.rs, tcp.rs, iroh.rs}` 構造で確認 (`mod.rs` 343 行 / `tcp.rs` 884 行 / `iroh.rs` 273 行) |
| 依存追加 | `Cargo.toml:50-52` に `iroh = "0.91"`, `data-encoding = "2.4"`, `qrcode = "0.12"` |
| `chat_loop` 汎用化 | `mod.rs:133-342` で `R: AsyncReadExt + W: AsyncWriteExt` ジェネリックに変更済 |
| 共通ロジックの再利用 | `read_vec` / `write_vec` / `update_transcript` / `read_line_secure` / `chat_loop` が `mod.rs` に集約 |
| `TransportKind::Iroh` デフォルト化 | `src/config.rs:49-52` で確認 |
| `--transport iroh\|tcp` CLI | `src/main.rs:108` で確認 |
| Iroh ハンドシェイク基本構造 | ECC-DH + ML-KEM の二重共有秘密 + HKDF-SHA3-256 でキー導出 (`iroh.rs:131-160, 241-261`) |
| 既存 TCP テストの非破壊 | TCP 版 `cooldown` / `abort` 系テストは `tcp.rs` に残置 |

---

## 優先度サマリ

Phase 1 の体裁は整っているが、**Phase 1 完了 = 認証なしで動く E2E チャットがデフォルトで起動する状態**。現状をそのまま開発ブランチに残すと危険。

優先度高い順:

1. **F-IROH-01 / F-IROH-10** (Critical, 認証層の完全欠落) — Phase 2 を待たずに対処が必要
2. **F-IROH-12** (Medium, テスト不在) — F-IROH-01/10 への対処と同時に Iroh トランスポート用テストを追加すべき
3. **F-IROH-04 / F-IROH-05 / F-IROH-06** (High, 認可・セッション管理・channel binding) — Phase 2 と並行
4. **F-IROH-02** (Medium, ticket 強化) — Phase 2 のスコープ通り
5. **F-IROH-03 / F-IROH-07 / F-IROH-11** (Medium, プロトコル設計の前向き整理) — Phase 3 まで
6. **F-IROH-08 / F-IROH-09 / F-IROH-13** (Low, 既知の引き継ぎ事項)

---

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体計画。Phase 2 のスコープ確認に使用。
- `PHASE1_COMPLETION_REPORT.md` — 検証対象の完了レポート。
- (未作成) `THREAT_ANALYSIS_NN.md` — Iroh 化後のスコープで新規脅威分析サイクルが必要。
