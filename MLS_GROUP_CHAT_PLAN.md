# MLS グループチャット 実装計画書

`nkCryptoTool-rust` に **真の E2E グループチャット**を追加するための実装指示書。
プロトコルは **MLS (Messaging Layer Security, RFC 9420)**、暗号は既存 Hybrid モードと整合する **ハイブリッド ciphersuite (ECDH P-256 + ML-KEM-768)** を採用する。

## 0. このドキュメントについて

現状の `nkct/chat/1` は厳密に 2 者専用 ハンドシェイクであり、3 人以上の安全な
グループ会話を成立させられない。本計画は IETF 標準の MLS を採用してこのギャップを
埋める。1:1 チャットは併存して残し、新しい ALPN `nkct/mls/1` 上で動作する別系統と
して実装する。

目的:

- **PQC ネイティブ E2E グループチャット**: 通信に関わる全暗号要素を hybrid PQC で
  覆い、量子計算機による Harvest-Now-Decrypt-Later 攻撃に対し復号不能を保証する。
- **後方/前方秘匿性 (PFS + PCS)**: メンバーの 1 デバイス compromise から自動回復
  する設計。MLS の TreeKEM ratchet が提供。
- **メンバー変更コスト O(log N)**: 数十〜数百人のグループでも join/leave/remove が
  実用速度で完結する。
- **標準準拠**: RFC 9420 準拠の wire format を採用し、将来的に他 MLS 実装
  (Wickr / Wire / mls-rs ベースの他ツール) と相互運用可能な余地を残す。

非ゴール:

- 1:1 チャット (`nkct/chat/1`) の置き換え。既存の peer-to-peer 直接対話は残す。
- メタデータ秘匿 (誰が誰と話しているか)。MLS は内容を守るが、コネクション・トポロジ
  自体は隠さない。
- 中央リレーサーバの導入。配信は Iroh の既存 P2P (および将来の `iroh-gossip`) に
  乗せる。

----

## 1. ゴールと非ゴール（詳細）

### 1.1 ゴール

| 項目 | 詳細 |
|---|---|
| グループサイズ | 〜100 メンバー (実用想定)、〜1000 (技術上限) |
| 主要暗号 | ハイブリッド PQC: ECDH (P-256) + ML-KEM-768 (鍵交換), ML-DSA-65 (署名), AES-256-GCM (AEAD), SHA3-256 (KDF/Hash) |
| Forward secrecy | epoch ratchet による |
| Post-compromise security | TreeKEM Commit で全鍵回転、新規 KeyPackage で復帰 |
| 永続化 | ローカル sqlite ファイル (鍵は zeroize-on-drop) |
| 再開 | プロセス再起動後もグループ状態を復元できる |
| CLI / GUI | 両対応。CLI で create-group / join / send、GUI で member list + chat view |

### 1.2 非ゴール

- 複数デバイスでの単一ユーザー同期 (1 デバイス = 1 MLS member)。
- グループ間のクロスプロトコル相互運用 (RFC 9420 互換だが、独自 KeyPackage 配布
  形式)。
- 写真・動画などのバイナリ添付。本計画はテキスト + 軽量ファイル (≤1 MiB) のみ。

----

## 2. 設計原則

### 2.1 アプリ起点で API を定義する（最重要）

`mls_rs::Client::create_group` などのライブラリ API をそのまま外部に出さない。
アプリが本当に必要とする操作 (create / join / send / receive / add / remove /
leave / list_members) のみを公開し、mls-rs の型は `crate::group::` 内に閉じ込める。

### 2.2 transport 抽象 (`crate::p2p`) の上に乗せる

MLS は transport-agnostic な仕様。Iroh QUIC でも mock duplex でも動作することを
利用し、`GroupChatProcessor` は `Arc<dyn P2pEndpoint>` を受け取る (現行
`NetworkProcessor` と同じ DI パターン)。

### 2.3 鍵は `Zeroizing<T>` で揃える

mls-rs の内部鍵管理が完璧でも、本プロジェクトの境界に出る鍵 (sender keys のスナップ
ショット等) は `Zeroizing` でラップし drop 時消去を保証する。

### 2.4 エラーも抽象化する

mls-rs のエラー型をそのまま `?` で伝播させない。`GroupError` を定義し、ライブラリ
固有エラーは `Backend(String)` に正規化する。

### 2.5 非同期前提・キャンセル安全

`async_trait` を用いる。`recv` 系はキャンセルされうる前提で書き、`tokio::select!`
下で安全に使えること。

----

## 3. ライブラリ選定

### 3.1 採用ライブラリ

| クレート | バージョン | 役割 |
|---|---|---|
| `mls-rs` | 最新 (2026-05 時点 0.50+) | MLS 本体実装 (Apache-2.0, AWS+Cisco maintained) |
| `mls-rs-crypto-openssl` または `mls-rs-crypto-rustcrypto` | 同上 | base CryptoProvider (本プロジェクトの既存 backend と整合) |
| `mls-rs-codec` | 同上 | TLS Presentation encoding |
| (永続化) | mls-rs 本体の `MlsConfig::with_storage` に sqlite ストレージを差し込む。 | |

### 3.2 採用根拠

- **Apache-2.0** で本プロジェクト (MIT) と互換。
- AWS / Cisco がプロダクション運用 (Webex)。
- WASM サポート済み (将来 web 版に展開可)。
- `CryptoProvider` / `CipherSuiteProvider` trait を経由した拡張点が用意されており、
  PQC 拡張を自前で組み込める。
- tokio 親和性: async API、`Send + Sync` 境界がアプリと一致。

### 3.3 重要: PQC 専用 crate は **存在しない**

`mls-rs-crypto-pqcrypto` のような off-the-shelf PQC ciphersuite crate は **AWS Labs
リポジトリにも crates.io にも存在しない** (2026-05 時点)。MLS の PQC 対応は draft
段階で、widely-deployed なライブラリ実装はまだない。

→ 本プロジェクトでは **自前で `CipherSuiteProvider` を実装する** (詳細は §5.4
crypto_adapter)。これは追加工数だが、副次的に大きなメリットがある:

- プロジェクトに既に存在する PQC 実装 (`backend::pqc_keygen_kem`, `pqc_sign`,
  `pqc_decapsulate` 等) を **MLS 層が再利用できる**。OpenSSL backend 経由なら
  既に FIPS 認定パスに乗っている。
- 1:1 chat と group chat で **同一の PQC 実装に統一**できる。crypto agility が
  保たれる。

### 3.4 不採用ライブラリ

| クレート | 不採用理由 |
|---|---|
| `openmls` | 開発活発だが API が頻繁に breaking change。AWS の mls-rs の方が安定 |
| 自前 MLS 実装 | RFC 9420 全文 ~300 ページ。crypto レベルで致命的バグの危険。NO |

----

## 4. Ciphersuite 選定

### 4.1 採用 ciphersuite

draft MLS PQC hybrid suite (RFC 9420 register に申請中の番号空間)。

具体:
- **HPKE KEM**: X25519MLKEM768 (X25519 + ML-KEM-768 結合 KEM)
- **AEAD**: AES-256-GCM (AES-NI 加速可)
- **Hash / KDF**: SHA-256 / HKDF-SHA256 (MLS 標準では SHA-256 必須)
- **Signature**: HybridMLDSA65Ed25519 (ML-DSA-65 + Ed25519 結合署名)

**Ed25519 を採用する理由** (Ed448 ではなく):
- Rust エコシステムで `ed25519-dalek` / `ring` 等の選択肢が豊富で枯れている。
- Ed448 のネイティブ実装は希少で、特に RustCrypto 系では満足な crate がない。
- セキュリティ強度は本ハイブリッド構成のボトルネック ML-DSA-65 (≥128 bit
  post-quantum) で決まり、Ed448 の +α は本シナリオで価値が薄い。

### 4.2 既存 Hybrid モード (`CryptoMode::Hybrid`) との関係

- 既存 1:1 Hybrid: ECDH P-256 + ML-KEM-768。本計画では X25519 へ変更
  (MLS 標準準拠のため)。
- 既存の鍵ファイル (`*_ecdh.key`, `*_mlkem.key`) は MLS 用 KeyPackage を別途生成する
  必要があり、**新規ファイル群を別ディレクトリに置く** (例: `keys/mls/`)。
- 既存 1:1 と MLS は鍵を共有しない (異なる ALPN、異なる KeyPackage)。

### 4.3 SHA-256 と SHA3-256 の関係

本プロジェクトは SHA3-256 を多用 (HKDF, transcript, ticket SID 等) が、MLS 標準は
SHA-256。**MLS スコープ内では SHA-256 に従う**。既存の SHA3 利用箇所には影響しない。

----

## 5. アーキテクチャ

### 5.1 モジュール構成

```
src/
  group/
    mod.rs               # 公開 API: GroupChatProcessor, GroupError, GroupId
    state.rs             # GroupState (mls-rs Group をラップ)
    storage.rs           # 永続化 (sqlite ベース、mls-rs storage trait 実装)
    invite.rs            # Welcome / KeyPackage の配布ヘルパ
    message.rs           # アプリレベル message framing (本文 + sender metadata)
    processor.rs         # GroupChatProcessor 本体 (P2pEndpoint を所有)
    crypto_adapter/      # PQC ハイブリッド CipherSuiteProvider 自前実装
      mod.rs             # HybridCryptoProvider
      kem.rs             # X25519 + ML-KEM-768 結合 KEM (HPKE 内部)
      signature.rs       # ML-DSA-65 + Ed25519 結合署名
      key_schedule.rs    # HKDF-SHA256 等の標準操作 (base provider に委譲)
  p2p/                   # 既存。新 ALPN `nkct/mls/1` を IrohEndpoint::new で登録
```

### 5.2 中核型

```rust
/// MLS グループの識別子。GroupId は MLS 内部で 32 バイト乱数。
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct GroupId(pub [u8; 32]);

/// メンバーの識別子。MLS の LeafNode ED-SPKI 等価のフィンガープリント。
/// 既存の crate::p2p::PeerId と意図的に区別する (デバイス対応関係が異なるため)。
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct MemberId(pub [u8; 32]);

/// グループメッセージ。本文は UTF-8 lossy で扱う (既存 chat と同じ defensive)。
pub struct GroupMessage {
    pub sender: MemberId,
    pub epoch: u64,
    pub timestamp_ms: u64,
    pub body: String,
}

/// MLS グループ操作の正規 API。
pub trait GroupChatBackend: Send + Sync {
    async fn create_group(&self, name: &str) -> Result<GroupId, GroupError>;
    async fn join_group(&self, welcome: &[u8]) -> Result<GroupId, GroupError>;
    async fn leave_group(&self, gid: &GroupId) -> Result<(), GroupError>;

    async fn add_member(&self, gid: &GroupId, key_package: &[u8]) -> Result<Welcome, GroupError>;
    async fn remove_member(&self, gid: &GroupId, member: &MemberId) -> Result<(), GroupError>;

    async fn send_message(&self, gid: &GroupId, body: &str) -> Result<(), GroupError>;
    async fn recv_message(&self, gid: &GroupId) -> Result<GroupMessage, GroupError>;

    async fn list_members(&self, gid: &GroupId) -> Result<Vec<MemberId>, GroupError>;
    async fn list_groups(&self) -> Result<Vec<GroupId>, GroupError>;
}

pub struct Welcome {
    pub recipient: PeerAddr,            // 配送先 (transport は別系)
    /// MLS Welcome (TLS-presentation 形式)。本体は受信者の HPKE 公開鍵で
    /// 暗号化されているが、グループ参加に必要な秘密がパッケージされている
    /// ため defense-in-depth で drop 時にゼロ化する。
    pub bytes: Zeroizing<Vec<u8>>,
}

#[derive(thiserror::Error, Debug)]
pub enum GroupError {
    #[error("group not found")]
    NotFound,
    #[error("not a member of group")]
    NotMember,
    #[error("invalid welcome / key package")]
    InvalidWelcome,
    #[error("transport: {0}")]
    Transport(#[from] crate::p2p::P2pError),
    #[error("storage: {0}")]
    Storage(String),
    #[error("backend: {0}")]
    Backend(String),
}
```

### 5.3 transport 統合

新 ALPN を `IrohEndpoint::new` の protocols に追加 (Cargo.toml 不要、コード変更のみ):

```rust
// src/network/mod.rs
pub const ALPN_MLS: &[u8] = b"nkct/mls/1";

// src/p2p/backend/iroh.rs (IrohEndpoint::new 内)
let protocols = vec![
    P2pProtocol(ALPN_CHAT),
    P2pProtocol(ALPN_FILE),
    P2pProtocol(ALPN_MLS),    // ← 新規
];
```

`GroupChatProcessor` は `Arc<dyn P2pEndpoint>` を受け取り、`endpoint.connect(addr,
P2pProtocol(ALPN_MLS))` で他メンバーに MLS フレーム (Welcome / Commit / Application)
を送る。

### 5.4 受信メッセージのディスパッチ

`ALPN_MLS` で受信したストリームの内容は単一の MLS フレームではなく、以下のいずれか:

| MLS message タイプ | 受信側の挙動 |
|---|---|
| `Welcome` | 新規グループへの招待。`Client::join_group` で受け入れ判断 |
| `Application` | 既存グループのメッセージ。該当グループの `process_incoming_message` |
| `Commit` | メンバー追加/削除等の状態遷移。epoch 更新後にローカル state を保存 |
| `Proposal` | 提案のみ (Commit で確定するまで保留) |

`mls-rs` は受信バイト列を `MlsMessage` enum に decode することでこれらを判別できる
(`MlsMessage::deserialize`)。`GroupChatProcessor` は受信ストリームから 1 メッセージを
読み出した時点で type に応じて分岐する。

将来的に複数フレームを 1 ストリームでまとめて送る最適化を入れる余地もあるが、初版は
**1 接続 = 1 MlsMessage** を原則とする (1:1 chat と同じシンプルさ)。

### 5.5 PQC ハイブリッド CipherSuiteProvider (`crypto_adapter/`)

`mls-rs` の `CipherSuiteProvider` trait を自前で実装する。中核設計:

```rust
pub struct HybridCryptoProvider<B: CipherSuiteProvider> {
    base: B,  // mls-rs-crypto-openssl::OpenSslCryptoProvider 等
}

impl<B: CipherSuiteProvider> CipherSuiteProvider for HybridCryptoProvider<B> {
    // 標準操作 (AEAD / KDF / Hash / MAC) は base に丸投げ
    fn aead_seal(...) { self.base.aead_seal(...) }
    fn hkdf_expand(...) { self.base.hkdf_expand(...) }
    fn hash(...) { self.base.hash(...) }
    // ...

    // KEM / Signature だけ override してハイブリッド化
    fn kem_generate(&self, ...) { /* X25519 + ML-KEM-768 結合 */ }
    fn kem_encapsulate(&self, ...) { /* 両 KEM の結果を HKDF で結合 */ }
    fn kem_decapsulate(&self, ...) { /* 同上 */ }
    fn sign(&self, ...) { /* ML-DSA-65 sig || Ed25519 sig */ }
    fn verify(&self, ...) { /* 両方検証して両方 OK のときのみ true */ }
}
```

PQC 部分は本プロジェクトの `crate::backend::pqc_keygen_kem` / `pqc_sign` 等の既存
実装に委譲し、ECC 部分 (X25519 / Ed25519) は `ring` または `ed25519-dalek` /
`x25519-dalek` に委譲する。結合方式 (Concatenated KEM / Composite Signature) は
NIST 移行ガイドラインおよび MLS draft に従う。

工数感: **約 500-800 行** + テスト。最大の山場だが、ここを越えれば mls-rs 本体は
そのまま使える。

----

## 6. 状態モデルと永続化

### 6.1 グループ状態

mls-rs の `Group` 型は内部で TreeKEM ratchet, sender keys, application secrets 等を
保持する。本プロジェクトでは:

```rust
struct GroupState {
    inner: mls_rs::Group<MlsConfig>,    // mls-rs 本体
    name: String,                        // ユーザー表示用
    created_at: u64,                     // unix ms
}
```

`mls-rs` 自体が永続化対応 (state を bytes に serialize 可) なので、独自シリアライズは
不要。アプリ側は `state.rs` で取りまとめる。

### 6.2 ストレージ

| データ | 形式 | パス例 |
|---|---|---|
| KeyPackage (自分) | DER | `keys/mls/keypackage.bin` |
| 署名鍵 (自分) | PKCS#8 | `keys/mls/signing.key` |
| グループ状態 | sqlite via mls-rs-provider-sqlite | `groups/<group-id-hex>.db` |
| Welcome 受信箱 | sqlite (pending welcomes) | `groups/welcome-inbox.db` |

ファイル権限は既存 `0o600` 方針を踏襲。`keys/mls/signing.key` は passphrase 保護
(既存 utils::extract_raw_private_key パターン)。

### 6.3 ゼロ化方針

- mls-rs 内部の鍵は同クレートが zeroize 対応
  (`zeroize` feature を有効化することを Cargo.toml で明示)。
- アプリ境界で取り出す中間バッファ (Welcome bytes、Commit message bytes) は
  `Zeroizing<Vec<u8>>` でラップ。

### 6.4 SQLite チューニング (async 競合対策)

グループ状態 sqlite は **同時書き込み競合**で `database is locked` を出しやすい。
初期化時に必須:

```sql
PRAGMA journal_mode = WAL;       -- 読み書き並行性
PRAGMA busy_timeout = 5000;      -- 5 秒待機
PRAGMA synchronous = NORMAL;     -- WAL 下なら安全な妥協
```

接続プーリングは **read 用は複数、write 用は単一接続**に制限する (multi-writer は
WAL でも sqlite の制限)。`r2d2` + `rusqlite` 想定。

### 6.5 署名鍵の in-memory キャッシュ

MLS の Commit (member 追加/削除/key update) は毎回 `sign` を呼ぶため、passphrase で
保護された署名鍵を**都度復号→破棄**するとパスフレーズ入力地獄になる。

採用ポリシー:
- セッション開始時 (CLI 起動 or GUI ログイン時) に**一度だけ**復号、`Zeroizing<Vec<u8>>`
  + `mlock` 配下に保持。
- セッション終了時 (プロセス終了 / 明示的 `--lock-keys`) で zeroize。
- `--key-cache-timeout <sec>` で最後のアクセスから N 秒で自動 zeroize するオプション
  (default = 無効、明示有効化のみ)。
- 本キャッシュは `crate::p2p::backend::iroh::NetworkProcessor` 既存の Lazy Loading 鍵
  管理と**異なる**運用 (1:1 chat は per-handshake load、group は per-session load)。
  違いを SECURITY.md に明記する。

----

## 7. プロトコルフロー

### 7.1 グループ作成

```
A (creator)
  ├── 既存 signing key + KEM key を読み込み
  ├── mls_rs::Client から KeyPackage を生成 (自分用)
  ├── Client::create_group(group_id, ciphersuite, signing_identity)
  │     → 1 名グループ生成 (自分のみ)
  └── storage に GroupState 保存
```

### 7.2 招待 (Welcome) の配送

```
A: group.add_member(B's KeyPackage)
  → (Commit, Welcome) を取得
  → Commit は既存メンバーへブロードキャスト
  → Welcome は B に直接送信 (Iroh で B の PeerAddr へ ALPN_MLS で接続)
B: Welcome を受信
  → Client::join_group(welcome_bytes)
  → ローカル GroupState を構築 → storage 保存
  → ack を A に返す
```

B の KeyPackage を A が事前に取得する経路:
- 短期: ファイル経由 (B が `nk-crypto-tool --export-key-package > b.kp` を作成、
  A に渡す)
- 中期: Ticket 拡張で KeyPackage を埋め込む
- 長期: Iroh の discovery service 上に published

### 7.3 メッセージ送信

```
A: group.encrypt_application_message(body)
  → MlsMessage (Private) を取得
  → メンバー全員 (自分以外) に Iroh ALPN_MLS で配送
  → 自分の表示用には別途ローカル echo (MLS は self-message を再復号できない設計)
B,C,...: recv → group.process_incoming_message(mls_msg)
  → ApplicationMessage を抽出 → body を UI に表示
```

配送モデル: **N-1 unicast**。Iroh gossip があれば multicast 化可だが、初版は unicast
で十分 (N≤100 想定)。

### 7.4 メンバー削除

```
A: group.propose_remove(member_id)
  → Proposal を全員に配送
  → 即 Commit (single-step remove)
  → 新 epoch の鍵を全員が導出
  → 削除されたメンバーは新鍵で復号不能 (= PCS 成立)
```

### 7.5 シーケンス図

```
  A          B          C
  │← KeyPkg ─│          │       // A は事前に B の KeyPackage を入手
  │ create_group(A)               // C は既メンバーと仮定
  │  ↓ add_member(B's KP)
  │  ⇒  (Welcome, Commit) を生成
  │  -- Welcome -------→ │       // B 専用 (B の HPKE 公開鍵で暗号化)
  │  -- Commit  -------→ │       // B 側でも epoch 適用
  │  -- Commit  -------------→ │  // 既存メンバー C にも配送
  │                B.join_group(welcome_bytes)
  │                B.process_message(commit)   // B も同じ epoch に到達
  │
  │ send "hello"
  │  ⇒  App message (epoch N, encrypted)
  │  -- App ------------→ │ recv & decrypt
  │  -- App ------------------→ │ recv & decrypt
```

要点:
- `add_member` は **Welcome と Commit を同時に生成**する。Welcome は新メンバー専用
  (Welcome 自体に新 epoch の secret が HPKE 暗号化されて入っている)、Commit は
  既存メンバーへの状態遷移指示。
- 新メンバー B は Welcome を受けて `join_group` し、続けて到着する Commit を
  `process_message` で適用することで、既存メンバーと同一の epoch に到達する。
- mls-rs の実装上は Welcome 単体で B が group state を完全に復元できるよう設計
  されているため、Commit を別経路で送る必要は厳密にはないが、Commit ブロードキャストは
  既存メンバー側で必須。

----

## 8. CLI / GUI 統合

### 8.1 CLI フラグ追加

```bash
# グループ作成
nk-crypto-tool --mode hybrid --create-group "my-team"

# KeyPackage 書き出し (B が A に渡すため)
nk-crypto-tool --mode hybrid --export-key-package > my.kp

# 招待 (A が B を追加)
nk-crypto-tool --group-id <hex> --add-member b.kp --recipient-addr <PeerAddr>

# 参加 (B が Welcome 受信時)
nk-crypto-tool --listen   # ALPN_MLS で Welcome を待ち受け、自動 join

# 送信
nk-crypto-tool --group-id <hex> --send "hello team"

# 受信 (対話モード)
nk-crypto-tool --group-id <hex> --chat-group
```

### 8.2 GUI (Slint)

既存の 1:1 chat 画面の隣に `GroupList` パネル追加。
各グループに対し: メンバー一覧、メッセージ履歴、送信ボックス。
管理者操作 (Add/Remove) はサブメニュー。

GUI 統合の優先度は低い (CLI が動けば PoC として十分)。

----

## 9. テスト戦略

### 9.1 mock backend 上の決定的テスト

P2P 抽象の `MockEndpoint` を使い、グループ操作を **完全に決定的に**検証する:

| テスト | 内容 |
|---|---|
| `mock_create_and_send_single_member` | 1 名グループで自送信→自受信が成立 |
| `mock_three_member_handshake` | A が B,C を招待、3 者間でメッセージ往復 |
| `mock_remove_member_pcs` | C を remove 後、C は新メッセージを復号不能 |
| `mock_concurrent_proposals` | A と B が同時に Proposal、Commit 順序解決 |
| `mock_persist_and_reload` | グループ作成→drop→sqlite から再読込→状態一致 |

### 9.2 iroh 上の integration test

`#[ignore]` 付き integration test (CI で `--ignored` job のみ実行):
- 3 ノードを起動、Iroh ALPN_MLS で招待→送受信→remove のフルシナリオ
- 既存 e2e テストの規約に従う

### 9.3 fuzz / 負の経路

- 改竄された Welcome 受信 → `InvalidWelcome` で拒否
- 古い epoch の Application message → 自動破棄 (mls-rs が標準で処理)
- 自分が削除された後の受信 → `NotMember` で停止

### 9.4 性能テスト

- 100 メンバーグループの remove (TreeKEM の O(log N) 検証): 中央値 < 100ms 目標
- 1KB メッセージの encrypt: 中央値 < 1ms 目標

----

## 10. CI への組み込み

`.github/workflows/rust.yml` に追加:

```yaml
jobs:
  group-mls-tests:
    needs: p2p-abstraction-check
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Build with mls feature
      run: cargo build --features mls
    - name: Run mock-backend MLS tests
      run: cargo test --features mls group::
```

新 feature flag `mls` を Cargo.toml に追加し、デフォルト無効 (まず opt-in)。
本実装が安定したら default に昇格。

----

## 11. セキュリティ脅威モデル

### 11.1 想定攻撃者

| 攻撃者 | 防御 |
|---|---|
| ネットワーク受動傍受 (ISP, WiFi) | TLS 1.3 + MLS による二重暗号 |
| ネットワーク能動 (MITM) | MLS の per-epoch authentication + 既存 ticket fingerprint |
| 退会メンバー (元同僚) | PCS により新メッセージは復号不能 |
| 単一メンバー compromise (デバイス盗難) | 削除 + 新 epoch で全鍵更新 |
| プロセス・メモリダンプ (gcore, /proc/mem) | Zeroize で短時間残存最小化、長期鍵は passphrase 保護 |
| 量子計算機 (将来) | ハイブリッド ML-KEM-768 で復号不能 |

### 11.2 想定外 (out-of-scope)

- TPM/HSM へのハードウェアバインディング (将来課題)
- メタデータ秘匿 (誰とどの epoch でやり取りしているか)
- フォーク攻撃 (Malicious server-style fork): MLS は本来 fork 検知機構あり (epoch
  authenticator) だが、初版では単純 trust-on-first-Welcome のみ実装

### 11.3 不変条件

- グループ鍵は MLS Welcome / Commit 経路以外でメモリ外に出ない
- ファイル永続化される鍵は必ず passphrase 暗号化 or `0o600` mode + mlock
- 退会後のローカル states は明示的に削除可能 (`--purge-group <id>`)

----

## 12. 既知の制約とトレードオフ

| 制約 | 理由 | 緩和策 |
|---|---|---|
| 1 デバイス = 1 MLS member | MLS 仕様。多デバイスは仕様 v2 で対応予定 | 当面は「PC / モバイル = 別 member」と運用 |
| Welcome 配送に専用フロー必要 | MLS 自体は配送方式を規定しない | 初版は Iroh 直 unicast。将来 ticket 拡張 |
| グループ状態の DB 破損 | sqlite ファイル破損で参加不能 | バックアップ + Welcome を保管していれば再 join 可 |
| 順序保証なし | MLS application messages は順序非保証 | アプリ側で timestamp ベースに並べる |
| 大規模 (N>1000) は未検証 | mls-rs ベンチ未実施 | 段階的に増やす |
| 大規模 (N>50) で N-1 unicast が遅い | Iroh QUIC 接続が並列に N-1 必要 | 初版は PoC。将来 `iroh-gossip` か中継リレーで multicast 化 |
| PQC ciphersuite の RFC 9420 番号未確定 | IETF draft 段階 | 暫定 IANA 私有番号空間を使用、確定後に reassign |

----

## 13. 受け入れ基準 (DoD)

- [ ] `src/group/` に Public API trait と型が定義され、外部から `mls_rs::` 型が
      見えない (`! grep -rn 'mls_rs::' src/ --include='*.rs' | grep -v 'src/group/'`)。
- [ ] `src/group/crypto_adapter/` がハイブリッド `CipherSuiteProvider` を実装し、
      `pqc_*` バックエンドへの委譲が動作。non-PQC base と PQC 拡張が混在せず排他。
- [ ] CLI から `create-group / export-key-package / add-member / send / chat-group`
      の一連が動く。
- [ ] mock backend 上で§9.1 の 5 テストが green。
- [ ] iroh 上の 3 ノード integration test が `--ignored` でも実行可能。
- [ ] グループ状態の永続化 (sqlite) と再読込が成立。
- [ ] PCS テスト: remove 後の退会者が新メッセージを復号できないことを確認。
- [ ] `cargo test` で全テスト pass、`cargo audit` でクリーン。
- [ ] README / SPEC に MLS グループチャットセクション追加。

----

## 14. 段階的進め方

| Phase | 内容 | 完了条件 |
|---|---|---|
| **P1** | Cargo.toml に mls-rs + `mls-rs-crypto-openssl` 依存追加、feature flag `mls` 整備、`src/group/` 骨格作成、**`crypto_adapter` 雛形**(`mls-rs-crypto-openssl` を base にした passthrough)| `cargo build --features mls` が通る、簡単な non-PQC ciphersuite で create_group が動く |
| **P1.5** | `crypto_adapter` の **PQC 部分実装** (X25519+ML-KEM-768 結合 KEM、ML-DSA-65+Ed25519 結合署名)。RustCrypto/OpenSSL backend の `pqc_*` を再利用 | ハイブリッド ciphersuite で MLS の `create_group` → `add_member` のローカル round-trip が成立 |
| **P2** | `GroupState` + sqlite 永続化 (WAL/busy_timeout 設定込み)、create-group / list-groups 実装 | mock 上で create→drop→reload テスト green |
| **P3** | KeyPackage 生成 + 書き出し、Welcome 受信ロジック、署名鍵の in-memory cache | export-key-package → join-group のローカル往復 |
| **P4** | `nkct/mls/1` ALPN 統合、Iroh 経由 Welcome / Commit / Application の routing (受信時の MlsMessage type 分岐) | 2 ノード間で実際に Welcome 配信成功 |
| **P5** | Application message 送受信 (3 メンバーまで) | mock 上で 3 者間メッセージ往復 |
| **P6** | Add member / Remove member + PCS 検証 | remove テスト green |
| **P7** | CLI 仕上げ (--chat-group 対話モード)、エラーメッセージ整備 | E2E (CLI) シナリオが通る |
| **P8** | GUI 統合 (オプション) | グループ一覧 + 送受信 UI |
| **P9** | README / SPEC 更新、レポート作成 | ドキュメント完了 |

**P1 と P1.5 を分けた理由**: PQC ハイブリッド `CipherSuiteProvider` の自前実装が
本計画最大の技術リスク。まず non-PQC base ciphersuite で MLS 統合の他要素 (sqlite,
ALPN, processor 骨格) を全部通してから、後で PQC 拡張を差し替える。これにより PQC
実装の問題と MLS 統合の問題を切り分けられる。

各 Phase で個別コミットを切り、レビュー可能なサイズを保つ。

----

## 15. アンチパターン (やってはいけないこと)

- `mls_rs::*` 型を `src/group/` 外に漏らす。
- MLS 内部鍵を `String` / `Vec<u8>` のまま長期保持 (必ず `Zeroizing` 経由)。
- 1:1 chat (`nkct/chat/1`) のコードを破壊する。グループは新規 ALPN で並列実装。
- mls-rs のエラーをそのまま `?` で伝播 (`GroupError::Backend(String)` で抽象化)。
- 仕様変更を勝手に行う (RFC 9420 準拠が必須)。
- Welcome を平文ファイルとしてディスクに残し続ける (受信処理後は削除)。
- 「自分用 echo」を MLS で送ろうとする (MLS は self-message 復号できない設計)。
- CLI と GUI で別々の永続化スキーマを作る (sqlite を 1 系統に統一)。

----

## 16. 参考資料

- [RFC 9420 - The Messaging Layer Security (MLS) Protocol](https://datatracker.ietf.org/doc/html/rfc9420)
- [mls-rs リポジトリ](https://github.com/awslabs/mls-rs)
- [mls-rs ハイブリッド PQC 対応](https://github.com/awslabs/mls-rs/tree/main/mls-rs-crypto-pqcrypto)
- 本プロジェクトの `p2p-abstraction-spec.md` (transport 抽象化の前提)
- 本プロジェクトの `SECURITY_PROFILE.md` (1:1 chat の脅威モデル評価)
- `mls_group_chat_review.md` (本計画書 v1 に対する技術レビュー。v2 (本版) で
  全フィードバックを反映済み: `mls-rs-crypto-pqcrypto` の実在性訂正、Ed25519
  採用、N-1 unicast スケール限界の明示、SQLite WAL/busy_timeout、署名鍵の
  in-memory cache、MLS message type ディスパッチ、Welcome の Zeroizing 化、
  PQC ciphersuite Phase の P1/P1.5 分割)

---

*この計画書は実装着手前のレビュー資料である。実装中に判明する技術的詳細
(mls-rs API の細部、ハイブリッド ciphersuite の最終番号など) により細部は調整される
余地を残す。Phase ごとにコメントを反映し、最終的に `MLS_GROUP_CHAT_REPORT.md` として
完了報告書を生成する。*
