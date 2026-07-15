# P2P 層 抽象化 実装レポート

外部仕様書 `p2p-abstraction-spec.md` に基づく、P2P 通信層の iroh からの疎結合化作業の記録。

- 作成日: 2026-05-24
- 対象: `src/p2p/` (新設) / `src/ticket.rs` / `src/network/` / `src/gui/mod.rs` / `Cargo.toml` / `.github/workflows/rust.yml` / `scripts/check_p2p_abstraction.sh` (新設)
- 関連コミット: `48ca2467`, `11bdba81`, `ef29719c`, `8afb4f27` (origin/main へ push 済み)

---

## 1. 目的

`p2p-abstraction-spec.md` §0 に基づき、移行の有無に関わらず得られる以下の便益を確保する。

- **テスト容易性**: ネットワークを張らないモック実装を差し込み、flaky な iroh / e2e テストの一部を決定的なユニットテストへ置き換える素地を作る。
- **関心の分離**: アプリ本体のロジックから `iroh::Endpoint` や `NodeId` などの具体型を排除する。
- **依存の局所化**: iroh の breaking change の影響を1モジュール内に閉じ込める。
- **要件の明文化**: 自アプリが P2P に本当に求める操作を trait として言語化する。

将来的な `libp2p` 等への差し替え余地確保は副次的な恩恵。

---

## 2. 実装方針 (仕様書からの調整)

### 2.1 仕様書からの逸脱と根拠

| 項目 | 仕様書原案 | 採用方針 | 根拠 |
|---|---|---|---|
| 層構成 | 3 層 (Endpoint → Connection → Stream) | **2 層 (Endpoint → Stream)** | 現アプリは「1 接続 = 1 双方向ストリーム」固定 (chat / file_transfer どちらも `accept_bi`/`open_bi` 1 本のみ)。Connection 層は仕様書§2.3 末尾の選択肢どおり省略 |
| 非同期方式 | `async_trait` または RPITIT | **`async_trait` (0.1)** | `dyn P2pEndpoint` 対応が必要 (mock 差し替えのため)。RPITIT は dyn-compat に難 |
| ALPN の扱い | (明示なし) | **`connect` 引数 + 構築時 protocol set 固定** | iroh の ALPN 多重化と整合。`accept` は negotiated protocol を返す |
| `PeerId` 表現 | `[u8;32]` 想定 | **`pub struct PeerId([u8;32])` + hex Display/FromStr** | iroh::NodeId と等しいサイズ、文字列化は CLI 用途で hex が扱いやすい |

### 2.2 ファイル構成 (仕様書§3 と一致)

```
src/
  p2p/
    mod.rs          # 公開 API: trait と型の re-export
    types.rs        # PeerId, PeerAddr, P2pError, P2pProtocol
    traits.rs       # P2pEndpoint, P2pStream, P2pIncoming
    backend/
      mod.rs
      iroh.rs       # iroh 実装。iroh への依存はここに局所化
      mock.rs       # tokio::io::duplex によるインメモリ実装
scripts/
  check_p2p_abstraction.sh  # iroh-crate 漏れの grep 検出
.github/workflows/rust.yml  # p2p-abstraction-check ジョブ追加
```

---

## 3. インターフェース要点

### 3.1 型

```rust
// 識別子: newtype, hex Display/FromStr
pub struct PeerId([u8; 32]);

// transport-agnostic 接続情報 (iroh::NodeAddr 相当)
pub struct PeerAddr {
    pub peer_id: PeerId,
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<SocketAddr>,
}

// ALPN multiplexing identifier
pub struct P2pProtocol(pub &'static [u8]);

// エラー (iroh の生エラーは漏らさない)
pub enum P2pError {
    Connect(String), Accept(String), Send(String), Recv(String),
    Unreachable, Closed, InvalidPeerId, Backend(String),
}
```

### 3.2 Trait

```rust
pub trait P2pStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: ?Sized + AsyncRead + AsyncWrite + Send + Unpin> P2pStream for T {}

pub struct P2pIncoming {
    pub peer_id: PeerId,
    pub protocol: P2pProtocol,  // 受信ストリームの negotiated ALPN
    pub stream: Box<dyn P2pStream>,
}

#[async_trait]
pub trait P2pEndpoint: Send + Sync {
    fn local_id(&self) -> PeerId;
    async fn connect(&self, addr: &PeerAddr, protocol: P2pProtocol)
        -> Result<Box<dyn P2pStream>, P2pError>;
    async fn accept(&self) -> Result<P2pIncoming, P2pError>;
    async fn close(&self) -> Result<(), P2pError>;
}
```

### 3.3 設計判断のメモ

- **`accept` は protocol を返す**: サーバはどの ALPN で接続されたかを知る必要がある (iroh のセマンティクスと一致)
- **`connect` で protocol を指定**: クライアントは送る ALPN を選ぶ (iroh の `endpoint.connect(addr, alpn)` と一致)
- **構築時 protocol set 固定**: iroh::Endpoint は `.alpns(...)` で事前登録が必要。同じ集合を `IrohEndpoint::from_endpoint(endpoint, protocols)` で渡し、`accept` で照合して未知 ALPN を弾く
- **`Box<dyn P2pStream>` で返す**: blanket impl + `?Sized` で dyn-compatible

---

## 4. backend 実装

### 4.1 `backend/iroh.rs` (本実装)

#### `IrohBiStream` (AsyncRead + AsyncWrite wrapper)
iroh の `SendStream`/`RecvStream` は分離された 2 つの half で、quinn 由来の独自エラー型 (`WriteError`/`ReadError`) を返す。`AsyncRead + AsyncWrite` 1 つの object に束ねるため `Pin::new` で各 half を委譲し、エラーは `io::Error::new(ErrorKind::Other, e)` で変換。

```rust
fn map_io<T, E: std::error::Error + Send + Sync + 'static>(
    p: Poll<Result<T, E>>,
) -> Poll<io::Result<T>> {
    p.map(|r| r.map_err(|e| io::Error::new(io::ErrorKind::Other, e)))
}
```

#### `IrohEndpoint` (P2pEndpoint 実装)
- `local_id`: 構築時に `endpoint.node_id().as_bytes()` をキャッシュ
- `connect`: `PeerAddr` → `iroh::NodeAddr` 変換 → `endpoint.connect(node_addr, alpn).await` → `open_bi` → `IrohBiStream`
- `accept`: `endpoint.accept().await` → `incoming.accept()` → `connecting.alpn().await` で ALPN を取得 → `protocols` リストと照合 (未知 ALPN は `P2pError::Accept`) → `connecting.await` で `Connection` → `accept_bi` → `IrohBiStream`
- `close`: `endpoint.close().await`

#### iroh ↔ PeerAddr 変換ヘルパ
```rust
fn peer_addr_from_iroh(addr: &iroh::NodeAddr) -> PeerAddr { /* ... */ }
fn iroh_node_addr_from_peer(addr: &PeerAddr) -> Result<iroh::NodeAddr> { /* ... */ }
```

### 4.2 `backend/mock.rs` (テスト用)

`MockNetwork` (共有レジストリ) + `MockEndpoint` (per-node) の 2 構造体。

- 内部: `tokio::io::duplex(64KB)` で双方向 in-memory ストリーム生成
- ルーティング: `mpsc::unbounded_channel<P2pIncoming>` で connect→accept を結線
- 同期: `std::sync::Mutex` (await 跨ぎなしの短時間ロックのみ)
- ALPN セマンティクス: iroh 実装と対称 (構築時に登録した protocol しか受け付けない)

#### 制約 (意図的)
- パケット損失・再順序・遅延のシミュレーションは**しない**。これらが必要なテストは別途敵対的ストリームを構築せよ
- NAT 越え・リレー・実 discovery の検証は**できない**。それらは引き続き iroh 実装に対する `#[ignore]` 付き統合テストで行う (仕様書§5)

---

## 5. ticket.rs の iroh 型排除

旧 `Ticket::new(node_addr: iroh::NodeAddr, ...)` と `Ticket::node_addr() -> Result<iroh::NodeAddr>` は唯一の真の iroh 漏れだった。

| 項目 | 旧 | 新 |
|---|---|---|
| 入力 | `iroh::NodeAddr` | `PeerAddr` |
| 出力 | `Result<iroh::NodeAddr>` (fallible) | `PeerAddr` (**infallible**) |
| import | `use iroh::{NodeId, NodeAddr, RelayUrl}` | (撤去) |
| 内部表現 | `[u8;32]` / `String` / `Vec<SocketAddr>` | 不変 (既にアプリネイティブ) |

`peer_addr()` が infallible になったのは、`Ticket` の内部表現がもともとアプリネイティブだったため変換不要だから。iroh::NodeAddr への変換は `backend/iroh.rs` の `iroh_node_addr_from_peer()` ヘルパに集約。

---

## 6. CI による抽象化漏れ検出 (`scripts/check_p2p_abstraction.sh`)

```bash
# 検出パターン: src/p2p/backend/iroh.rs 以外で `use iroh::*`
# / `use iroh_base::*` / `use iroh_relay::*` を検出
PATTERN='^[[:space:]]*use[[:space:]]+iroh(_base|_relay)?(::|;|[[:space:]])'
FORBIDDEN=$(grep -rEn "$PATTERN" src/ --include='*.rs' | grep -v "^src/p2p/backend/iroh.rs:")
```

意図的に拾わない:
- doc コメント (`//! iroh::X`, `/// iroh::X`)
- 自前モジュールパス (`crate::p2p::backend::iroh::*`)

`.github/workflows/rust.yml` に `p2p-abstraction-check` ジョブを追加 (build matrix の手前で軽量に走るので壊れたら即気付ける)。

正常時と違反挿入時の両方で動作確認済み (`exit 0` / `exit 1`)。

---

## 7. 検証結果

| 項目 | 結果 |
|---|---|
| OpenSSL backend build (release) | ✅ |
| RustCrypto backend build (release) | ✅ |
| lib 単体テスト | **22 passed**, 8 ignored (mock 4 件新規追加で 18→22) |
| 既存 streaming_v3 テスト | 14 passed (振る舞い不変) |
| `scripts/check_p2p_abstraction.sh` | ✅ クリーン (iroh 漏れなし) |
| ticket round-trip | sha256 一致 (既存) |
| chat 接続 (iroh 経由) | UTF-8 fix と組み合わせ動作確認済み (前セッション) |

### 7.1 新規 mock テスト (4 件)
1. `roundtrip_message_via_trait`: 2 ノード間の双方向バイト交換が trait 経由で動く
2. `connect_to_unregistered_peer_is_unreachable`: 未登録 PeerId への connect が `P2pError::Unreachable` になる
3. `connect_with_unregistered_protocol_fails_locally`: 未登録 ALPN で connect が事前拒否される (半開き状態を peer に届けない)
4. `accept_reports_negotiated_protocol`: ALPN 多重化で正しい protocol が返る

---

## 8. 仕様書§7 DoD 達成状況

| DoD 項目 | 状態 | 備考 |
|---|---|---|
| `src/p2p/` に trait と型が定義、公開 API として re-export | ✅ | `mod.rs` で集約 |
| 既存 iroh コードが `backend/iroh.rs` に移送、振る舞い不変 | ✅ | ファイル移動 + path 更新のみ |
| `backend/iroh.rs` 以外に `iroh::` 出現なし (grep 通過) | ✅ | doc/自前パスは正常に除外 |
| モック実装と決定的ユニットテスト少なくとも1つ green | ✅ | **5 件 green**（mock 4 + processor handshake 1）|
| アプリ本体が trait 越しにのみ P2P を利用 | ✅ | `NetworkProcessor` は `src/p2p/processor.rs` に移送され、内部処理は `self.endpoint: Arc<dyn P2pEndpoint>` 経由のみ |
| iroh エラーが `P2pError` に変換、生のまま漏れない | ✅ | `IrohEndpoint` 実装ですべて map |
| CI に 3 系統 (grep / mock / 実ネット分離) | ✅ | grep 新規, mock は通常 `cargo test`, 実ネットは既存 `#[ignore]` |

**DoD 全項目達成。**

---

## 9. 経過 (フェーズ別)

実装は 6 フェーズに分割して進めた。各フェーズで個別にコミットし、検証を挟みつつ段階的に到達。

| フェーズ | 内容 | 主担当 | コミット |
|---|---|---|---|
| Phase 1 | `local_addr` を trait に追加 + 各 backend 実装 | この session | `3b5c2377` |
| Phase 2 | `IrohEndpoint::new(config, is_test)` ファクトリ追加 | 同上 | (同コミット) |
| Phase 3a | NetworkProcessor 構造体 DI 化 (`endpoint: Arc<dyn P2pEndpoint>` 保持, コンストラクタ統合, GUI/tests 全更新) | この session | `8355c134` |
| Phase 3b | NetworkProcessor 内部メソッドの本格 trait 化 (create_endpoint/EndpointGuard 廃止, accept_bi/open_bi → trait.accept/connect, NodeId → PeerId, tokio::io::split で stream を半割り) | Antigravity 経由 | `a49cbb4a` |
| Phase 4 | NetworkProcessor を `src/p2p/processor.rs` に移送 (transport 非依存層へ昇格) | 同上 (Phase 3b と同コミット) | (同) |
| Phase 5 | `network/mod.rs` / `gui/mod.rs` / `tests/e2e_file_transfer.rs` を新 API に追従 | 同上 | (同) |
| Phase 6 | mock backend 上の決定的プロトコルテスト追加 | 同上 | (同) |

Phase 3b 〜 6 は外部実装 (Google Antigravity) により1コミットで完結。内部メソッド refactor は約 1000 行に及び、リスクの高い「ライブ secure transport」を扱うため、振る舞い不変リファクタに徹する原則を守って遂行された。

---

## 10. 検証結果 (最終)

| チェック | 結果 |
|---|---|
| OpenSSL backend build (release) | ✅ |
| RustCrypto backend build (release) | ✅ |
| 全テスト (`cargo test`) | **53 passed, 14 ignored**（11 suites）|
| lib 単体テスト | 23 passed |
| `scripts/check_p2p_abstraction.sh` | ✅ クリーン |
| `src/p2p/backend/iroh.rs` 行数 | 1300+ → **609** (NetworkProcessor 抽出で大幅縮小) |
| `src/p2p/processor.rs` (新規, 抽象 NetworkProcessor) | 755 行 |

---

## 11. 結論

**P2P 抽象化は完成した。**

| 項目 | 状態 |
|---|---|
| 抽象化の基盤 (trait / 型 / エラー正規化) | ✅ 完成 |
| iroh-crate の局所化 | ✅ 完全 (`backend/iroh.rs` 内のみ) |
| CI による自動検出 | ✅ 稼働 |
| mock backend と決定的テスト | ✅ 5 件 (mock 4 + processor handshake 1) |
| `IrohEndpoint` 完全実装 | ✅ |
| **`NetworkProcessor` の trait 経由化** | ✅ **完了**（`src/p2p/processor.rs`、transport 非依存）|
| アプリ全体が trait 越しにのみ P2P を利用 | ✅ |

仕様書 §7 DoD 全項目を満たし、§0 の便益（テスト容易性・関心の分離・依存の局所化・要件の明文化）はすべて確保された。将来的な `libp2p` 等への差し替え (副次目的) も、`backend/` 下に並列実装を追加するだけで成立する設計に到達している。
