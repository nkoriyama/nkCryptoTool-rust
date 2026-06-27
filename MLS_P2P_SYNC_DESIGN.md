<!--
  本書は agy 生成の初稿 (mls_p2p_sync_design.md) を、現行コードベース
  (redb 移行済み / P2pEndpoint 現行シグネチャ / 既存 allowlist) と
  SPEC.md §16 の不変条件に照らして Claude がレビューし改訂した版である。
  初稿との主な差分:
    - ストレージを SQLite → redb (アプリ層 AEAD seal) に訂正 (§4)
    - 【新規】PeerId ↔ MLS メンバーのマッピングを最重要前提として明記 (§2)
    - epoch 保持の二重基準 (state N=3 vs commit 履歴) と
      oldest_retained_epoch の定義を明確化 (§4.2)
    - disconnect_peer に必要な接続レジストリを IrohEndpoint 要件として追加 (§3.2)
  実装着手前に末尾「未決定の論点」を確定すること。
-->

# 設計提案 (改訂版): MLS グループ状態と P2P トランスポートの同期

> [!CAUTION]
> **2026-06-27 撤回**: 本書が設計する **transport allowlist へのゲートキーピング/エビクション投影
> (Invariant 1/2)** は機能として**撤回**した。実装直前の精査で、MLS グループの本体
> (チャット/ファイル) は `ALPN_MLS` 上の MLS Application メッセージとして流れ、**MLS 自身が
> 暗号保護** (機密性・完全性・前方秘匿・PCS) しており、かつ招待 (Welcome) のため非メンバーにも
> 到達可能でなければならないと判明した。`PeerId` allowlist が gate しうる transport データプレーン
> (`ALPN_CHAT`/`ALPN_FILE` の 1:1 フロー) は**MLS グループメンバー間では使われない**ため、
> ロスターを transport gate へ投影しても MLS 以上のセキュリティを足さず、むしろ可用性・正当性の
> 実害 (招待/inbox 遮断、ML-DSA 指紋ではなく iroh ノード id で gate する同一性の取り違え) を
> 生む。**実装として残すのは**: Invariant 0 (MLS が source of truth — 矛盾しうる弱い transport
> 投影が存在しないだけ)、Invariant 3 (mls-rs が Remove で epoch 前進・鍵更新)、
> Invariant 4〜6 (コミット履歴に基づく delta **Resync プロトコル**。SYNC 応答は現ロスター非メンバーを
> 拒否)。`update_allowed_peers` / 能動エビクション (Invariant 1/2) は意図的に不在。
> 以下の §3 (gate/eviction 設計) は**歴史的記録**であり、現行コードには対応しない。

本書は `nkCryptoTool-rust` の MLS グループメンバーシップを P2P トランスポート層
(`P2pEndpoint` / `NetworkProcessor` の allowlist) に同期させ、[SPEC.md §16](SPEC.md)
の不変条件 (Invariant 0〜5) を満たすための実装設計である。

> [!IMPORTANT]
> **現状 (2026-06)**: SPEC §16 のトランスポート同期層は**ほぼ未実装**。
> mls-rs が提供する MLS 内部の epoch 単調性・Remove 時の原子的鍵更新
> (Invariant 3) のみ成立しており、Invariant 0/1/2/4 と遅延 resync (§16.6) は
> 新規実装が必要。本書はその net-new 設計である。

---

## 0. 現状コードの確認結果 (実装の出発点)

| 層 | 既存実装 | ファイル |
| :-- | :-- | :-- |
| P2pEndpoint トレイト | `local_id` / `local_addr` / `connect` / `accept` / `close` のみ | `src/p2p/traits.rs` |
| IrohEndpoint | `endpoint` / `local_id` / `protocols`。allowlist 状態・epoch なし。`accept()` は ALPN 検証のみ | `src/p2p/backend/iroh.rs` |
| allowlist | `cached_allowlist: HashSet<[u8;32]>`、**起動時に静的ファイルから 1 回ロード**、動的更新・エビクション無し | `src/p2p/processor.rs` (`preload_allowlist`) |
| MLS Commit | `add_member` / `remove_member` → `apply_pending_commit` → `write_to_storage`。**トランスポートへの通知なし** | `src/group/processor.rs` |
| ロスター / epoch | `list_members` は `MemberInfo { index }` のみ (**PeerId 無し**)、`group.current_epoch()` | `src/group/processor.rs` |
| 永続化 | **redb** (`mls_group_state` / `mls_epoch`(直近 N=3) / `mls_key_package` / ...)。`group_commits` 無し | `src/group/redb_storage.rs` |
| epoch 単調性 | inbox `checkpoint(peer, epoch) -> CheckpointOutcome` (per-peer、ロールバック検出)。**ただし GroupChatProcessor から未使用** | `src/group/redb_storage.rs` |

---

## 1. 不変条件と実装状況のマッピング (SPEC §16)

| 不変条件 | 内容 | 現状 | 本書で実装 |
| :-- | :-- | :-- | :-- |
| 0 | MLS が権限の source of truth、transport はその投影 | ✗ 接続点なし | ✓ §3 |
| 1 | `update_allowed_peers(set, epoch)`、epoch 単調 | ✗ | ✓ §3.1 |
| 2 | 新接続は T=0 拒否 / 既存は T 秒以内に切断 | ✗ | ✓ §3.2 |
| 3 | Remove で即 epoch 前進・鍵更新 | ✓ mls-rs | (既存) |
| 4 | 古い epoch のピアは resync (在籍時) / 即時拒否 (エビクト済) | ✗ | ✓ §5 |
| 5 | 楽観的 epoch 前進 + 遅延 resync | 部分 (broadcast のみ) | ✓ §5 |

---

## 2. 【最重要前提】PeerId ↔ MLS メンバーのバインディング

> [!WARNING]
> SPEC §16 の「MLS ロスター → allowlist へ投影」(Invariant 0/1) は、
> **MLS の各メンバーを transport の `PeerId` に対応付けられること**を暗黙の前提とする。
> 現状 `MemberInfo` は leaf index しか持たず、この対応付けが存在しない。
> **これを定義しないと本設計全体が成立しない。** 初稿はこの点を欠いていた。

> [!IMPORTANT]
> **【2026-06 訂正】初稿/前版は「同一の ML-DSA 鍵を両層で使う」前提だったが、
> 現行コード調査で誤りと判明した。** 実際には 2 つの identity は**完全に別物**:
> - **MLS 署名 identity**: Hybrid (`Ed25519 ‖ ML-DSA-65`)、redb `mls_app`
>   (`mls:identity:sk/pk`)、グループ初期化時に生成 (`crypto_adapter.rs`)。
> - **transport 認証 identity**: `ML-DSA-65` 単独、PKCS#8 PEM ファイル
>   (`--signing-privkey`)、アプリ起動時に別途用意。
>
> 鍵の**種類すら異なる** (hybrid vs ML-DSA 単独) ため「同一鍵 + ドメイン分離」は
> 成立しない。**ユーザー決定 (2026-06): 束縛署名方式を採用** (§7.6 確定)。

### 2.1 バインディング方式 (束縛署名)
2 つの独立した identity を、**MLS 署名 identity による束縛署名**で結ぶ:
- transport identity = ML-DSA-65 公開鍵。allowlist/`PeerId` エントリはその
  **SHA3-256 指紋 (`[u8;32]`)** (既存 `cached_allowlist` と同形式)。
- **束縛署名**: メンバーは自分の **MLS hybrid 署名鍵**で、ドメイン分離コンテキスト付きの
  メッセージ `BINDING_CONTEXT ‖ len ‖ transport_dsa_pub` に署名する
  (`binding = Sign_MLS(transport_dsa_pub)`)。これは「この MLS identity は transport 鍵 F を
  使う」という**MLS 側からの証明**。
- **完全な対応付けの成立**:
  1. MLS group が roster (= MLS 署名公開鍵の集合) を権威として保持 (Invariant 0)。
  2. 各メンバーの束縛署名が「MLS member M ↔ transport 指紋 F」を MLS 側で attest。
  3. transport ハンドシェイクで接続側が **F の秘密鍵支配を ML-DSA 署名で証明** (既存)。
  → (1)+(2)+(3) で「現に F を支配して接続してきたのは roster 上の M である」が確定。
- **なりすまし耐性**: 攻撃者メンバー M' が他人の F を束縛しても、transport ハンドシェイクで
  F の支配を証明できないため接続不可 (自己 DoS にしかならず、他者の F を乗っ取れない)。

### 2.2 影響
- `list_members` を拡張し、各メンバーの **MLS 署名公開鍵**を取り出せるようにする
  (`MemberInfo { index, signing_pub }`)。指紋投影はこの公開鍵と束縛署名から導出。
- 束縛署名の生成/検証プリミティブ (`src/group/binding.rs`) を**フェーズ 0** として最初に
  実装する (ネットワーク非依存・単体テスト可能)。束縛の交換/検証の配線はフェーズ 3/4。

### 2.3 ドメイン分離 (クロスプロトコル耐性)
- 束縛署名は **MLS 署名鍵**で行うため、MLS フレーム署名 (RFC 9420 ラベル付き) と
  混同されないよう、束縛メッセージは専用コンテキスト `"nkct-mls-transport-binding-v1"`
  を必ず前置する (一方の署名が他方の検証で通用しない)。
- transport ハンドシェイク署名 (ML-DSA-65) も従来どおり transcript 束縛されており、
  束縛署名 (MLS hybrid 鍵, 別コンテキスト) とは鍵も対象も異なる。
- 鍵が完全分離されたため、初版で懸念した「単一鍵多目的利用」リスクは**該当しない**
  (§7.6 で分離を確定)。

---

## 3. トランスポート層の拡張

### 3.1 P2pEndpoint トレイト (Invariant 0/1)
```rust
// src/p2p/traits.rs
#[async_trait]
pub trait P2pEndpoint: Send + Sync {
    // ... 既存 (local_id / local_addr / connect / accept / close) ...

    /// allowed peer 集合をスレッドセーフに更新する。
    /// `epoch <= 適用済み epoch` の更新は破棄する (単調性: Invariant 1)。
    fn update_allowed_peers(&self, allowed: HashSet<[u8; 32]>, epoch: u64) -> Result<(), P2pError>;

    /// 当該 PeerId の能動接続/ストリームを閉じる (Invariant 2 の既存接続側)。
    async fn disconnect_peer(&self, peer_fp: &[u8; 32]) -> Result<(), P2pError>;
}
```
- `PeerId` ではなく **`[u8;32]` 指紋**を鍵にする (既存 allowlist と統一)。
- **【レビュー反映】後方互換**: 新メソッドは**デフォルト実装付き**で追加する
  (`update_allowed_peers` = no-op で `Ok`、`disconnect_peer` = `Ok`)。これにより
  既存の `P2pEndpoint` 実装・テストモックがビルドエラーにならず、allowlist 同期を
  実装するバックエンド (IrohEndpoint) だけが override する。

### 3.2 IrohEndpoint の状態とゲートキーピング (Invariant 1/2)
追加状態:
```rust
allowed_peers: Arc<RwLock<Option<HashSet<[u8;32]>>>>, // None=未設定(全許可: 後方互換)
applied_epoch: Arc<AtomicU64>,
// disconnect_peer のために必要な能動接続レジストリ (初稿に無かった要件):
active_conns: Arc<Mutex<HashMap<[u8;32], Vec<ConnHandle>>>>,
```
- **`update_allowed_peers`**: `epoch <= applied_epoch` なら破棄 (CAS)。それ以外で
  `allowed_peers` を置換し `applied_epoch` を更新。
- **新接続のゲートキーピング (T=0)**: `accept()` 内、ML-DSA 認証で相手指紋が確定した
  **直後**に `allowed_peers` を照合し、集合が設定済みかつ不在なら**アプリ層ストリームを
  開く前に**接続を閉じる。
- **能動切断 (T=0, 猶予なし)**: `sync_transport_and_evict` で `old - new = evicted` を算出し、
  各 evicted について **即時** `disconnect_peer` する (`disconnect_peer` は他群に残るピアには no-op)。
  - **【レビュー反映・改訂】猶予窓は廃止**: 当初は QUIC テアダウンのため 3 秒の猶予を設けたが、
    猶予中も evicted ピアは既存の**データプレーン (`ALPN_CHAT`/`ALPN_FILE`) 接続**で送信を続けられる。
    データプレーンは生バイト列で **epoch 保護が無い** (MLS フレームと違い T=0 の epoch ローテで
    切れない)。よって猶予を設けず **T=0 で接続を切る**。
  - **【レビュー反映・重要】自己除外時の allowlist 失効**: 自ノードが群から Remove された
    (`CommitEffect::Removed`) 場合、当該群の allowlist 投影を `remove_group_membership(group_id)` で
    **即座に削除**し、`old_roster` の各ピアを `disconnect_peer` する (他群に残らないピアのみ切断される)。
    これを怠ると、除外後も元同群メンバーが自ノードのデータプレーンに接続し続けられる。
  - **【レビュー反映・重要】旧 epoch メッセージ受理の即時停止**: Invariant 3 が保護するのは
    **新** epoch (E) の鍵のみ。エビクト済みピアは依然 **旧 epoch (E-1) の鍵を保持**しており、
    MLS の epoch 遷移窓 (リオーダ許容) を悪用して**有効な E-1 アプリメッセージを送れる**。
    したがって Remove commit 適用と**同時に**、当該メンバーからの旧 epoch アプリメッセージの
    受理も打ち切る (group ごとの epoch 受理窓を締める / エビクト済み leaf を即時 deny)。
    「猶予中も無害」と仮定してはならない — 猶予は接続切断のみ、メッセージ受理は T=0 で停止。
  - `active_conns` レジストリは新規追加要件。`accept`/`connect` 成立時に登録し、
    切断/ドロップ時に解除する。
  - **【レビュー反映】エビクションと新接続登録の原子性 (TOCTOU 防止)**: `update_allowed_peers`
    は **(1) `allowed_peers` を更新 → (2) evicted の `active_conns` を close** の順で行い、
    accept 側の**ゲートキーピング照合と `active_conns` 登録を同一ロック下**で実行する。
    これにより「close sweep 直後に evicted ピアの接続が登録されて切断対象から漏れる」
    隙間を塞ぐ (登録時に最新 `allowed_peers` を再照合し、不在なら登録せず即閉)。

### 3.3 ゲート対象 ALPN スコープ (Invariant 2 の適用範囲) — 【レビュー反映・重要】
allowlist ゲートは **アプリ・データプレーン (`ALPN_CHAT` / `ALPN_FILE`) の inbound 接続のみ**
に適用する。**MLS 制御プレーン (`ALPN_MLS`: Welcome/Commit/Proposal) と inbox
(`ALPN_INBOX`) はゲート対象外**とする。理由:
- **`ALPN_MLS` をゲートすると multi-group 招待が壊れる**: 既に 1 つ以上の群に属する
  ノードは allowlist が非空になる。別の群へ招く相手はまだ共有ロスターに居ないため、
  全 ALPN をゲートすると inbound Welcome 接続まで拒否され、**新規群への参加が不可能**になる。
  MLS 制御プレーンは **mls-rs 自身が認証**する (招待されていない Welcome は復号失敗、
  非メンバーの Commit は検証失敗) ため、transport allowlist によるゲートは冗長かつ有害。
- **`ALPN_INBOX` は設計上オープン** (誰でもオフライン宛の非同期メッセージを預けられる)。
  ゲートすると非現メンバーからの store-and-forward 配送が壊れる。
- データプレーン (`ALPN_CHAT`/`ALPN_FILE`) は MLS 暗号化されない生の 1:1 payload を運ぶため、
  ここだけを「MLS 認証済みメンバーのみ」にゲートすれば目的を満たす。
- SYNC 応答 (`ALPN_MLS` 上) 自体は **roster membership チェック** (`accept_next` 内) で
  非メンバーを拒否するので、ゲート免除でも保護は維持される。

### 3.4 能動接続レジストリの掃除と SYNC レート制限
- **掃除**: `active_conns` への登録時に、既に閉じた接続 (`close_reason().is_some()`) を
  全 peer から sweep し、空エントリを除去する。これがないと**通常クローズ**で切れた接続が
  `disconnect_peer` まで残り続け、無制限リークになる (掃除コストは現存接続数で上限)。
- **SYNC DoS (受容済みトレードオフ)**: SYNC 応答は roster 取得のため membership チェック前に
  `load_group` を行うが、(a) 未知 group_id は redb の単純ミスで安価、(b) 実在 group_id でも
  redb 読取 1 回 (ホットならページキャッシュ)、(c) 各要求は QUIC ハンドシェイク+bi-stream を
  要し `accept_next` は直列・idle-timeout 済みで接続確立コストが自然なレート制限、
  (d) delta は `DEFAULT_COMMIT_RETENTION`/`oldest_epoch` で上限。実害は低い。
  **per-peer SYNC レート制限は将来のハードン候補**として残す。

### 3.5 受容済みトレードオフ / 将来要件 — 【レビュー反映】
- **HoL ブロッキング**: `accept_next` は直列ループで消費されるため、制御プレーンの読取・送信は
  `IDLE_TIMEOUT`(300s, バルク用) ではなく `HANDSHAKE_TIMEOUT`(10s) で上限を付ける:
  (a) ヘッダ読取、(b) SYNC 要求読取、(c) 標準 MLS フレーム body 読取
  (ALPN_MLS は制御プレーンで小サイズ。バルクはデータプレーン)、(d) **SYNC 応答全体**
  (OK マーカ+全コミットフレーム送信) を**単一の deadline**で囲む — per-write だけでは
  N コミット × timeout で総占有時間が無制限になるため。これで 1 接続あたりの占有を ~10s に抑える。
  接続確立 (QUIC) コスト+直列 accept が自然なレート制限。完全な並行化
  (接続毎タスク spawn) は将来の改善候補。
- **epoch = 0 (identity-level 束縛)**: `create_binding`/`verify_binding` は実装上 epoch=0
  に固定する。束縛が固定するのは長期 ID 鍵 `(mls_pub, transport_pub, peer_id)` そのもので、
  束縛の「リプレイ」= 自分の鍵での自 ID の再主張に過ぎず攻撃にならない。メンバーシップ権威は
  MLS ロスターが握る。transport 鍵のローテーション+失効を将来導入する場合のみ join-epoch
  束縛へ移行する。
- **群参加後のデータプレーン gate 常時化**: 1 つでも群に参加すると `allowed_peers` が非空になり、
  以後データプレーン (`ALPN_CHAT`/`ALPN_FILE`) は常にゲートされる (空=全許可は MLS 未参加時のみ)。
  これは MLS モードの意図した保護姿勢。現状 **leave/delete-group 操作は存在しない**ため
  「群を作成・削除して 1:1 を永久無効化」する DoS は到達不能。**将来 leave/delete-group を
  追加する際は、当該 group_id の `allowed_peers` エントリを除去するエンドポイントメソッドを
  必ず呼ぶこと** (さもないと stale エントリでデータプレーンが gate されたままになる)。
- **署名鍵ファイルの `exists()`→open TOCTOU (main.rs)**: ローカル FS を制御できる攻撃者が
  自ノードの署名鍵ファイルを差し替えるシナリオで、現状の脅威モデル外 (Windows ハードンも
  別途見送り中)。優先度低。

---

## 4. 永続化 (redb)

> [!IMPORTANT]
> 初稿は SQLite `group_commits` テーブルを前提にしていたが、本プロジェクトは
> **SQLCipher → redb へ移行済み (C-free)**。以下 redb で再設計する。

### 4.1 commit 履歴テーブル
```rust
// src/group/redb_storage.rs
const TBL_GROUP_COMMITS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("mls_group_commits");
const TID_GROUP_COMMITS: u8 = /* 次の未使用 ID */;
// key   = group_id(32) ‖ epoch(u64 BE)
// value = seal_value(k_value, db_binding, TID_GROUP_COMMITS, key, commit_bytes)
```
- commit メッセージは他レコード同様 **既存 `seal_value`(XChaCha20-Poly1305 + AAD=
  db_binding‖table_id‖key) で封緘**する (生保存しない)。
- 書き込み: `add_member` / `remove_member` / 受信 commit 適用時に `(group_id, epoch)`
  で INSERT。
- **【レビュー反映】正準 commit のみ保存 (フォーク上書き防止)**: 楽観配送下では同一 epoch に
  複数の有効な commit (フォーク) が生じ得るが、`(group_id, epoch)` キーは**ローカルが
  実際に適用して state を前進させた正準 commit** だけを格納する (我々が採用しなかった
  フォーク枝は保存しない)。ローカル MLS state は単一チェーンを辿るため、正準 commit は
  epoch ごとに一意。整合性のため value に **`confirmed_transcript_hash` を併記**し、
  resync 送出前/適用時に検証する (誤枝の混入検出)。
- **【レビュー反映】上書き時の nonce 安全性**: `seal_value` は**書き込みごとに新規ランダム
  24 バイト nonce (XChaCha20-Poly1305)** を引くため、同一キーを上書きしても nonce 再利用は
  起きない (正準 commit のみ格納するので上書き自体まれだが、起きても安全)。
- 読み出し (resync): `group_id` 一致かつ `epoch in (claimed_epoch, local_epoch]` を
  昇順 range scan。

### 4.2 epoch 保持の二重基準 (要明確化)
- **状態スナップショット** (`mls_epoch`): 直近 `DEFAULT_EPOCH_RETENTION_LIMIT = 3`。
- **commit 履歴** (`mls_group_commits`): より軽量なので長く保持可能 (既定: 直近
  `COMMIT_RETENTION = 100` epoch を提案)。
- **`oldest_retained_epoch` の定義 = commit 履歴側の下限** (resync 可否を決めるのは
  delta commit の有無であり、state スナップショットの数ではない)。
  - Case B (delta resync 可): `oldest_retained_epoch <= claimed_epoch < local_epoch`
  - Case C (Welcome fallback): `claimed_epoch < oldest_retained_epoch`
- 古い commit は `COMMIT_RETENTION` 超で prune (DB 肥大防止)。prune 量は `log()` 等で
  可観測にする (黙ってカバレッジを削らない)。

---

## 5. Resync プロトコル (Invariant 4 / §16.6)

### 5.1 順序: 認証 → 状態宣言 → ロスター照合 → 配送
1. **相互 ML-DSA 認証を先に完了**し、両者の `PeerId`(指紋) を暗号学的に確定する。
   **ロスター照合も resync データ配送も、相手の身元が証明されるまで実行しない**
   (victim の PeerId 詐称による resync 窃取・メンバーシップ探索の防止)。
   既存ハンドシェイクの transcript 束縛と同方針。
2. 認証後、接続側が `(claimed_group_id, claimed_epoch)` を暗号化チャネルで送る。
3. **ロスター照合** (確定した指紋を §2 のマッピングで MLS メンバーに対応付け):
   - **Case A (エビクト済)**: 現ロスターに不在 → **即時かつ恒久的に拒否**
     (古い epoch を騙った復帰攻撃の防止)。
   - **Case B (delta resync)**: 在籍 ∧ `oldest_retained_epoch <= claimed_epoch <
     local_epoch` → `mls_group_commits` から欠落 commit を昇順送出。straggler は順次
     適用し epoch と allowed_peers を現行へ前進。
   - **Case C (再招待が必要)**: 在籍 ∧ `claimed_epoch < oldest_retained_epoch`
     → delta 不能。
     > [!WARNING]
     > **【レビュー反映・重要】Case C で Welcome を自動再生成してはならない。** 再招待は
     > (a) straggler の**新しい KeyPackage を必要**とし (受信側が単独で Welcome を作れない)、
     > (b) **新たな Add commit = epoch 前進を伴うグループ状態変更**である。接続ごとに自動
     > トリガすると、攻撃者が任意の古い (または 0) epoch を申告して再接続を繰り返すだけで
     > **無限 commit ループ / グループ DoS** を誘発できる。「過去の Welcome を再生成」も
     > エフェメラル登録秘密を要し暗号学的に不可能。
     - 正しい扱い: 受信側は **resync 不能を straggler に通知し、再招待が必要な旨を
       シグナルするのみ** (自動 commit しない)。再 Add は straggler が新 KeyPackage を
       publish した上で、**意図的・レート制限付き**のグループ操作として実行する
       (誰が再 Add するか = committer の責務は §7 で確定)。
4. **epoch 単調性**: 受信側は処理後に既存 `checkpoint(peer_fp, epoch)` を呼び、
   `CheckpointOutcome::Rollback` なら resync を中止 (巻き戻し注入の防止)。現状未使用の
   この API をここで活用する。
5. **【レビュー反映】resync flood への DoS 対策**: 認証済みでも、極端に古い epoch の resync を
   連続要求して range scan で CPU/I-O を枯渇させ得る。**接続元指紋ごとに resync 要求を
   レート制限**する (既存 inbox FETCH のトークンバケット `FETCH_RL_*` と同方式)。加えて
   1 応答の commit 件数/バイト数に上限を設け、`oldest_retained_epoch` 未満の要求は
   range scan せず即 Case C へ落とす (無駄なスキャンを避ける)。

### 5.2 楽観的配送と結果整合性 (§16.6)
- commit はローカル適用後、到達可能なオンラインピアへ即時 broadcast (ACK 非待機)。
- オフライン/分割ノードは再接続時に上記 resync で単調にキャッチアップ。
- **既知の限界 (SPEC §16.6 が明記)**: 楽観的配送のため Remove のグローバル強制は
  結果整合。分割中のノードは commit 受信まで旧 epoch 鍵でエビクト済みメンバーと
  通信し得る。これは MLS-over-不安定網の固有性質であり、本設計は新たなリスクを
  足さない (ドキュメントに明示)。

---

## 6. 段階的実装計画

各フェーズはネットワーク無しでユニットテスト可能な単位に分割し、認証/メンバーシップ
経路を含むため各段で build → test → `/gemini-review` → 検証を行う。

- **フェーズ 0 — PeerId↔member バインディング (§2)**: credential への ML-DSA identity
  埋め込み、`MemberInfo` 拡張、ハンドシェイク鍵と credential の照合。**他の全ての前提**。
- **フェーズ 1 — 永続化 (§4)**: redb `mls_group_commits` テーブル + seal/range scan +
  prune。commit 適用時の保存。単体テストで往復・保持境界を検証。
- **フェーズ 2 — トランスポート拡張 (§3)**: `update_allowed_peers` / `disconnect_peer`、
  IrohEndpoint の `allowed_peers`/`applied_epoch`/`active_conns`、accept ゲートキーピング。
- **フェーズ 3 — MLS↔transport 配線 (§1,§3)**: commit 適用時に
  `endpoint.update_allowed_peers(roster→fps, epoch)` を呼び、evicted を grace 切断。
- **フェーズ 4 — Resync (§5)**: 状態宣言・Case A/B/C 分岐・commit 配送・Welcome
  fallback・checkpoint 連携。

### テスト戦略
- フェーズ 0/1: 単体 (マッピング一意性、commit 往復、保持境界、prune 可観測性)。
- フェーズ 2: 単体 (epoch 単調性で古い更新破棄、ゲートキーピング許可/拒否)。
- フェーズ 3/4: 敵対的 E2E (エビクト済みピアの新接続 T=0 拒否 / 既存接続 T≤3s 切断 /
  エビクト済みが古い epoch で resync を騙る → Case A 拒否 / straggler の Case B/C 復帰 /
  ロールバック注入 → checkpoint で中止)。

---

## 7. 未決定の論点 (実装着手前に確定)

1. **credential への identity 埋め込み形式**: ML-DSA SPKI 全体か指紋か。既存 KeyPackage/
   Welcome フォーマットとの後方互換 (既存グループ DB を壊さないか) を要確認。
2. **`COMMIT_RETENTION` の既定値**: 100 epoch で妥当か。ストレージ予算と「どれだけ長く
   オフラインだった member を delta 復帰させるか」のトレードオフ。
3. **grace 期間 T = 3s** の妥当性: ソケットフラッシュに十分かつエビクト済み接続を素早く
   切るバランス。Invariant 3 が二次防火壁である前提で妥当か最終確認。
4. **`active_conns` レジストリ**の iroh での実装 (接続ハンドルの保持と close API)。
5. **後方互換**: allowlist 未設定 (`None`) 時は全許可 (現行挙動維持) とするか、MLS 群では
   必須化するか。
6. **(確定 2026-06) identity 鍵の共有 vs 分離**: → **分離で確定**。現行コードで MLS
   (hybrid) と transport (ML-DSA 単独) は既に別鍵であり、§2 の束縛署名方式で結ぶ
   (ユーザー決定)。credential フォーマットは変更せず後方互換を保つ。
7. **(レビュー反映) Case C 再招待の主体**: 再 Add を誰が・どのレート制限で行うか
   (committer 権限・自動化の可否・straggler からの再招待要求プロトコル)。
8. **(レビュー反映) 旧 epoch 受理窓の締め方**: Remove 適用時にエビクト済み leaf の
   E-1 メッセージ受理を即時停止する具体機構 (mls-rs の epoch 受理窓 API との整合)。
