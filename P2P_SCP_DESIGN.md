# P2P SCP (`nkct/scp/1`) — 設計

踏み台レス・PQC 相互認証の P2P トランスポート上で、`scp` 相当のファイル転送を
提供する。`--serve-shell`（PTY シェル）・`--serve-forward`（ポートフォワード）に続く
第三のサービス ALPN。既存の `--connect < file`（ALPN_FILE ストリーム）が「一方向・
パス指定なし・認可なし」の生ストリームだったのに対し、本機能は **get/put・リモート
パス指定・fingerprint 単位の read/write 認可・パス confinement** を持つ本格版。

## 位置づけと非目標

- **やること**: 単一ファイル＋**ディレクトリツリー（`-r`）**の put / get、`--scp-policy`
  による read/write ルート認可、パス traversal / symlink escape の封じ込め（エントリ毎）、
  認証付きアトミックコミット（ファイル毎独立）、監査ログ。
- **やらないこと（次段）**: 並列ストリーム転送（`file_id` 多重化）、`user=` による
  per-request 権限降格、`Resume{offset}` 中断再開。フレーム集合はこれらを足せる形に
  予約済み。`--serve-scp` は root 実行を拒否し、ファイル I/O は常にサーバ起動ユーザ権限で
  行う（＝権限境界は「起動ユーザ ∧ policy ルート」）。

## トランスポート再利用

既存の共有 AEAD 基盤をそのまま使う（新規暗号なし）:

- `shell::send_packet` / `recv_packet` — `len(u32 LE) ‖ ciphertext ‖ tag(16)`、
  カウンタ nonce による replay/並べ替え/改竄検知。`MAX_PACKET = 128 KiB`。
- `shell::role_keys(s2c, c2s, is_server)` — 方向別鍵。
- ハンドシェイク・PQC 相互認証・allowlist は既存の `handle_server_connection` /
  `handle_client_connection` 経路を流用（shell/forward と同じ）。

データフレームは 1 パケットに収めるため **64 KiB** 単位でチャンクする。

## フレーム（`ScpFrame`、`shell::Frame` と同じ流儀の型タグ付き encode/decode）

| フレーム | 方向 | 内容 |
|---|---|---|
| `Put{ path, mode:u32, size:u64 }` | C→S | path へ size バイト書き込み要求 |
| `Get{ path }` | C→S | path の読み出し要求 |
| `Meta{ mode:u32, size:u64 }` | S→C | Get 応答ヘッダ |
| `Data(Vec<u8>)` | 双方向 | バルクバイト（≤64 KiB/フレーム） |
| `Eof` | 送信側→受信側 | バイト列終端 |
| `Ok` | 応答側 | 成功終端 |
| `Err(String)` | いずれか | 認可拒否・I/O 失敗など |

（予約・未実装: `List{path}` / `Entry{...}` / `ListEnd` / `MkDir{path,mode}` — `-r` 用。
`Resume{path, offset:u64}` — 中断再開用。v3 の File Session ID＋チャンクカウンタ資産を
使い staging temp への追記再開を許す拡張の席だけ予約する。「認証されるまで final に
出さない」不変条件と部分受信 temp の再検証の両立設計が要るため本増分では未実装。）

### `-r`（ディレクトリ再帰）の方針 — 直列先行・並列は席だけ予約

`-r` を入れる前に決めておく論点: **1 接続 1 ストリームで直列に流すか、QUIC の複数
ストリームで並列に流すか**。

- **直列**（採用予定）: フレームは今の `Put`/`Data`/`Eof` の繰り返し＋区切りで済み、
  エラー処理も直列。`scp -r` 互換の素朴さ。「認証されるまで final に出さない」不変条件は
  **ファイルごとに独立**（各ファイルを staging temp に受けてコミット）なので、部分失敗の
  セマンティクスが明快: 3/10 でクライアントが切断 → **コミット済み 3 件は完全＆認証済み・
  そのまま残る**、進行中 1 件は staging temp を破棄（final に出ない）、残り 6 件は未着手。
  サーバは `scp N/M transferred, failed at <path>` を監査に残す。分散トランザクション的
  複雑さは生じない。
- **並列**（次段・席のみ予約）: 小ファイル多数で QUIC の真骨頂（sendme 等に性能で並ぶ）。
  ただし不変条件をファイルごとに独立管理する複雑さと、N 本 in-flight の部分失敗状態の
  ハンドリングが生じる。

**流儀に沿った結論**: まず直列で実装し、ワイヤフレームに **ファイルごとの ID**（例
`Put{file_id, path, mode, size}` / `Data{file_id, ...}`）の席だけ予約しておく。将来
`file_id` 多重化で並列化しても直列クライアントと互換を保てる。素朴さ（scp -r 互換）を
今取り、性能（並列）は予約に留める。

#### 実装済み（直列）

プロトコルは *sender → receiver* 対称: 送信側が `MkDir` / `Put`+`Data`*+`Eof` をエントリ毎に
流し `Done` で締め、受信側が `Ack` / `Fail` をエントリ毎に返す。put ではクライアントが送信側、
get ではクライアントの `Get{path, recursive}` の後サーバが送信側になる。全 file-scoped フレームに
`file_id:u32` を付与（直列は連番、並列多重化の予約席）。

- **`-r` は「独立に confine された多数のエントリ」**: 各 `Put`/`MkDir` のパスを write ルート配下に
  個別 confine（`confine_write`/`confine_mkdir`）。ディレクトリ walk は**反復（明示スタック）**で
  深いツリーでもスタックオーバーフローしない。symlink は walk で辿らず（`file_type` 非追従）スキップ。
- **MkDir も open 後再検証**: 作成後に `canonicalize` して write ルート配下か再確認し、外れたら
  作成物を `rmdir` して拒否（`confine`→`create_dir` 間の中間 symlink すり替え TOCTOU 封じ。
  ファイルの `/proc/self/fd` 再検証と対をなす）。
- **部分失敗**: エントリ毎に `Ack`/`Fail`。confine 拒否・stage/commit 失敗は `Fail`（バッチ継続、
  ワイヤは一律 "denied"）。プロトコル違反（宣言 size 超過・想定外フレーム・ファイル途中で切断）は
  致命でストリームを閉じる。per-file 拒否でもファイル本文は宣言 size を上限に消費してストリーム同期を保つ。
- **get 側のローカル配置**: サーバが送るのはツリー相対パス。クライアントは `safe_join`（絶対・`..`・
  root/prefix コンポーネントを拒否）でローカル base 配下に限定。
- **非 Linux の限界**: 中間 symlink の open 後再検証（`/proc/self/fd`）は Linux 限定なのは単一
  ファイル時と同じ。運用は policy ルートをサーバ起動ユーザ所有・中間に非信頼書き込み無しを前提。

### `Err` のワイヤ表現 — 存在オラクル封じ

認可拒否とファイル不在をクライアントに区別して返すと、read ポリシー外パスの存在有無を
プローブできる oracle になる（`Err("not in read policy")` vs `Err("no such file")` の差で
ポリシー外ディレクトリを列挙できる）。よって**ワイヤ上の `Err` は拒否系を一律
`"denied"` に均一化**し、具体的理由は**監査ログにのみ**残す（ssh が認証失敗理由を
返さないのと同じ理屈）。転送中の I/O 失敗も一律 `"transfer failed"` とする。

### Put（アップロード）

```
C: Put{path, mode, size}
S: 認可(write) + confine。拒否なら Err("denied") で終了。
S: staging temp を O_NOFOLLOW|0600|create_new で final の同一ディレクトリに作成。
C: Data* → Eof
S: temp へ書き込み。Eof 受信で fsync → fchmod(mode & 0o0777) → atomic rename(temp→final)。
S: Ok（失敗時は Err、temp は破棄）
```

**size 強制**: `Data` の累計は宣言 `size` を上限として**到着ごとに**検査する。
超過（`received > size`）は即 `Err`＋転送中止（宣言を超えてストリームしてディスクを
埋める DoS を防ぐ）。`Eof` 時点で不足（`received < size`）も `Err`。＝宣言 size と実バイト数の
完全一致のみコミット。（予約: `--scp-policy` に per-root / global の最大サイズ上限を
持てる余地。公開 incoming 受け口運用で有効。）

各 `Data` は AEAD シールされカウンタ検証されるため、途中切断・改竄は復号失敗として
現れ **rename に到達しない**（`FileIOProvider::finalize_recv` と同じ「認証されるまで
最終パスに出さない」不変条件）。

### Get（ダウンロード）

```
C: Get{path}
S: 認可(read) + confine。O_NOFOLLOW で open、stat。拒否/不在なら Err("denied")。
S: Meta{mode, size} → Data* → Eof → Ok
C: ローカル書き込み先と同一ディレクトリの staging temp(O_NOFOLLOW|0600) に受信 →
   Ok+Eof で chmod → atomic rename → 受領 Ok(ack) を返して送信側を graceful close。
S: クライアントの ack / クローズ(EOF)を待ってから接続を閉じる。
```

**teardown レース対策(受領ハンドシェイク)**: サーバが終端フレーム送出直後に
`return`（＝ストリーム破棄）すると、まだ配送中のバルクデータが QUIC リセットで捨てられ、
クライアントは受信途中で「connection lost」になる（空ファイルは在庫が無く顕在化しない）。
よってサーバは**終端フレーム(Ok / Err)送出後、クライアントがドレイン＆クローズするまで
接続を保持**する（`drain_until_close`）。Get ではクライアントがコミット後に受領 Ok を返し
送信側を閉じ、Put ではクライアントが Ok を読んでから閉じる。この保持は認可拒否
（`Err("denied")`）にも適用し、拒否理由がクライアントへ確実に届くようにする。

Get 側 staging も **Put 側と対称に、最終ローカルパスと同一ディレクトリ**に temp を作る
（`/tmp` 等に置くと `rename` がクロスデバイス `EXDEV` で失敗する古典的罠を避ける）。
クライアントも `Meta{size}` を上限に到着ごとに超過を検査し、終端 `Ok` と `received==size`
の両方が揃って初めてコミットする（切断・水増しは公開されない）。

## 認可: `ScpPolicy`（`--scp-policy`、default deny）

`ForwardPolicy` / `ShellPolicy` と同じパーサ資産（`parse_fp_hex` /
`extract_quoted_span` / `extract_kv`）で組む。1 行 = 1 fingerprint:

```
# <sha3-256-hex>  read="root1, root2"  write="root3"   [user=NAME(予約)]
a6fc484e...  read="/srv/pub, /home/opc/out"  write="/home/opc/incoming"
```

- `read=` / `write=` は**許可ルート（ディレクトリ）**のカンマ区切り。最低 1 つ必須。
- fingerprint が policy に無ければ全拒否。read ルートに無いパスの Get、write ルートに
  無いパスの Put は Err。
- `user=` は本増分では**パースするが未強制・未記録**（予約のみ。権限降格と監査への
  記録はどちらも次段）。
- `mode` は**開いている fd に対して** `fchmod(mode & 0o0777)` で適用する。パスベースの
  `set_permissions(temp)` をクローズ後に呼ぶと、temp を symlink にすり替える TOCTOU で
  無関係ファイルを chmod されうるため、fd 経由にして封じる。マスクは `0o0777`＝
  **setuid/setgid/sticky を必ず除去**：アップロード（サーバ側）でもダウンロード
  （クライアント側）でも、ピアが選んだ権限昇格ビットを持つファイルは決して残らない。
  これは put/get 双方が共有する `Staged::commit` の一点で担保する。（予約: write ルート
  単位で mode をさらに絞る（umask 相当）余地。）

## パス confinement（本機能の要）

古典的な scp/rsync 脆弱面（`..` traversal・symlink escape）を封じる:

1. リクエストパスは**絶対パス**必須（相対は拒否）。
2. 各許可ルートを `canonicalize()`（symlink 解決済み実パス）。
3. リクエストパスを confine:
   - **Get**: フルパスを `canonicalize()`（存在するファイル）。
   - **Put**: 親ディレクトリを `canonicalize()`（ファイルは未存在で可）し、ファイル名を
     連結。ファイル名に `/` や `..` を含めない。
4. 正規化後パスが**いずれかの許可ルートの canonical プレフィックス配下**にあることを
   検証（`starts_with`、パス境界単位）。外れれば拒否。許可ルート自体は**policy load 時に
   一度だけ canonicalize** して保持する（per-request の I/O を無くし、ルートの意味を安定
   させる。解決できないルートは fail-closed で除外＝何も許可しない）。
5. 実 open は **`O_NOFOLLOW`**：最終コンポーネントが symlink なら失敗。
6. **open 後の再検証（中間ディレクトリ TOCTOU 封じ）**: `O_NOFOLLOW` は末尾しか守らず、
   check→open の間に**中間ディレクトリ**を symlink にすり替えられるとルート外へ逃げうる。
   そこで open 済み fd の実パスを Linux の `/proc/self/fd/<fd>` から取り、**カーネルが実際に
   辿った完全解決パスが依然ルート配下か**を再検証する（Get は開いたファイル、Put は
   staging temp の親ディレクトリ）。外れていれば拒否。Get の mode も**開いた fd の
   metadata**（fchmod 系の fstat）から取り、2 度目のパス解決で別 inode を掴む隙を無くす。

これにより「policy ルート ∧（末尾＋中間とも）symlink を辿らない ∧ 起動ユーザ権限」が
同時成立したパスだけが読み書きされる。（非 Linux では末尾 `O_NOFOLLOW`＋check-time
canonicalize までで、中間 symlink の open 後再検証は無い。運用上、policy ルートは
サーバ起動ユーザ所有で中間ディレクトリに非信頼書き込みを許さない構成を前提とする。）

## 起動時ゲート

- `--serve-scp` は `--scp-policy` 必須（無ければ起動拒否、default deny を担保）。
- `--serve-scp` は **root 実行を拒否**（serve-shell と同じ姿勢）。権限降格を持たない
  本増分では、root サーバは policy ルート外も物理的に書けてしまうため。
- 認証は既存どおり `--signing-pubkey`（ピン留め）＋任意 allowlist。未認証ピアは
  ALPN に関わらず shell/forward/scp を得られない。

## CLI

```bash
# サーバ
nkct --serve-scp --mode pqc --discovery n0 \
  --signing-privkey server.key --signing-pubkey client_pub.key \
  --scp-policy ./scp-policy --audit-log ./scp-audit.log

# クライアント: アップロード / ダウンロード（各 2 値: ローカル リモート）
nkct --scp-put ./local.bin /home/opc/incoming/local.bin --connect 'nkct1...' \
  --mode pqc --discovery n0 --signing-privkey c.key --signing-pubkey s_pub.key
nkct --scp-get /srv/pub/data.bin ./data.bin --connect 'nkct1...' ...
```

## 監査

`--audit-log` に 1 行/イベント（fingerprint 付き）: `scp allow put path=...`,
`scp deny: not in write policy`, `scp put ok bytes=...`, `scp get ok bytes=...`。
拒否は fail-closed（監査書き込み不能なら転送を拒否、shell と同様）。

## テスト

- ユニット: `ScpFrame` encode/decode ラウンドトリップ、切り詰めフレーム拒否、
  `ScpPolicy` パース、confinement（`..`・symlink・ルート外を全拒否、ルート内を許可）、
  **ゼロバイト staging の commit**（空ファイルが実体として残る）、未 commit drop で
  temp も final も残らない。
- 実機: VPS で `--serve-scp` を立て、256 KiB ランダムバイナリの put→get 往復を
  sha256 一致で検証。**境界値として 0 バイトファイルの put→get** も併せて確認。
