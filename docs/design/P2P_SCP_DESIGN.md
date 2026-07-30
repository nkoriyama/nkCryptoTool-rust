# P2P SCP (`nkct/scp/3`) — 設計

踏み台レス・PQC 相互認証の P2P トランスポート上で、`scp` 相当のファイル転送を
提供する。`--serve-shell`（PTY シェル）・`--serve-forward`（ポートフォワード）に続く
第三のサービス ALPN。既存の `--connect < file`（ALPN_FILE ストリーム）が「一方向・
パス指定なし・認可なし」の生ストリームだったのに対し、本機能は **get/put・リモート
パス指定・fingerprint 単位の read/write 認可・パス confinement** を持つ本格版。

## 位置づけと非目標

- **やること**: 単一ファイル＋**ディレクトリツリー（`-r`）**の put / get、`--scp-policy`
  による read/write ルート認可、パス traversal / symlink escape の封じ込め（エントリ毎）、
  認証付きアトミックコミット（ファイル毎独立）、監査ログ。
- **やらないこと（次段）**: 並列ストリーム転送（`file_id` 多重化）。nonce 分割
  （per-stream 鍵/nonce-prefix）が必須で、かつ**着手前に前提の再測定が要る**
  （→「並列ストリームの保留理由（2026-07-25 改訂）」）。
  `--serve-scp` は root 実行を拒否し、ファイル I/O は常にサーバ起動ユーザ権限で行う
  （＝権限境界は「起動ユーザ ∧ policy ルート」）。
- **`Resume`（中断再開）は実装済**（2026-07-16, `nkct/scp/3`）。単一ファイル get の
  `--scp-resume`。クライアントは中断時に `.<name>.nkct-partial` を残し、再 get で
  `Resume{path, offset, prefix_sha256}` を送る。サーバは `verify_resume` で「現 size ≥ offset
  ∧ 先頭 offset バイトの SHA-256 一致」を検証し、`ResumeFrom{offset}` を返す（一致=offset、
  不一致/縮小=0）＝同一接続で自動フルダウンロードに落ちる。「認証されるまで final にしない」
  不変条件は staging(.partial→rename)で維持。
- **`user=` は per-user インスタンスモデルで強制済**（`enforce_scp_user`）。in-process の
  権限降格は持たないので、`user=NAME` はそれが**サーバ自身のユーザ**を指す時のみ許可し、
  別ユーザ／未知ユーザを指す場合はセッションを拒否（fail closed）。別ユーザのファイルを
  配るにはそのユーザで別 `--serve-scp` を起動する。shell の Tier-1 `enforce_same_user` と同型。
  per-request setuid 降格は採らない（root 起動が前提になり root 拒否姿勢と矛盾するため）。

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

`Resume{path, offset, prefix_sha256}` / `ResumeFrom{file_id, mode, size, offset}` は
**実装済**（`--scp-resume`、上記「やらないこと」節参照）。部分受信 temp の再検証は
サーバ側 `verify_resume`（先頭 offset バイトの SHA-256 照合）で担保。

（予約・未実装: `List{path}` / `Entry{...}` / `ListEnd` — 将来の一覧用。）

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

#### ⚠ 上の「部分失敗のセマンティクス」は get `-r` では未実装（2026-07-25 確認）

直列を選んだ理由として上に挙げた「エラー処理も直列／部分失敗のセマンティクスが明快」は、
get `-r` の送信ループでは**まだ成立していない**。`src/scp.rs` のエントリ毎 ack 受信は

```rust
// Consume the client's per-entry ack (Ack/Fail); ignore its kind.
let _ = recv(&mut reader, aead_name, rx_key, &mut rx).await?;
```

で、`Ack` と `Fail` を判別していない。クライアントがディスクフル等で commit に失敗して
`Fail` を返しても、サーバはそれを見ずに次のエントリを送り続ける。中断が起きるのは接続
そのものが壊れた場合（`?`）だけ。したがってサーバ監査に残せるのは「送った」までで、
「相手が commit した」ではない。

**この往復は、対価を払って情報を受け取っていない状態**にある（ファイル毎に RTT 1 回。
RTT 100ms・10,000 ファイルなら約 1,000 秒が帯域・暗号速度と無関係に積まれる）。
正しい修正は ack の削除ではなく、**`Ack`/`Fail` を実際に判別して `Fail` で中断すること**。
そのうえで 1 ファイル毎に待たず N ファイル先行送信の窓を設ければ、RTT の大半を畳みつつ
上の約束を初めて実装できる（中断点の粒度は「失敗したファイル」から「窓の幅」に粗くなる
ので、その旨は監査に残す）。窓幅を固定値にすればワイヤのフレーム列は変わらず、
`nkct/scp/4` への flag-day を避けられる可能性がある。

#### 並列ストリームの保留理由（2026-07-25 改訂）

以前ここには保留理由として「WAN 網律速で見返り薄い」とだけ書かれていた（根拠:
`EVIDENCE 2.4.1`, 2026-07-02）。その記述には二つの問題がある。

1. **AEAD を容疑者から外した根拠が、既定バックエンドのものではない。**
   2.4.1 は `openssl speed` の ~23 GB/s を挙げて二重 AEAD を「主因でない（観測の 18 倍上）」
   と判定している。しかし既定バックエンドは `6458b021`（2026-06-18）以降 rustcrypto であり、
   測定はその 2 週間後。rustcrypto は `aes-gcm 0.11` 移行後で 1.07 GB/s、移行前はさらに低く、
   観測値 620 MB/s と同じ桁に隣接する。18 倍の余裕という前提は、既定構成では成立していない
   可能性が高い。**`aes-gcm 0.11` 後の再測定が、並列ストリーム要否を決める最も安い実験**
   であり、設計に着手する前にこれを行う。
2. **`-r` の支配項は帯域ではない。** 網律速の議論が成り立つのは大きな単一ファイルの WAN
   転送で、そこでは結論は今も有効（620 MB/s ≈ 5 Gbps は数百 Mbps の WAN より十分上）。
   一方 `-r` の小ファイル多数では、上記のエントリ毎 ack 往復（RTT × ファイル数）と、
   クライアント側 `commit` の毎回の `fsync`（`Staged::commit`）が支配する。並列ストリームは
   そのどちらにも効かない。

**着手順序**: ①`aes-gcm 0.11` 後の 2.4.1 再測定 → ②ack の `Fail` 判別＋窓化 → ③それでも
なお単一コア AEAD が回線を大きく下回ると測定で示された場合にのみ、並列ストリーム。

- **`-r` は「独立に confine された多数のエントリ」**: 各 `Put`/`MkDir` のパスを write ルート配下に
  個別 confine（`confine_write`/`confine_mkdir`）。ディレクトリ walk は**反復（明示スタック）**で
  深いツリーでもスタックオーバーフローしない。symlink は walk で辿らず（`file_type` 非追従）スキップ。
- **MkDir も open 後再検証**: 作成後に `canonicalize` して write ルート配下か再確認し、外れたら
  作成物を `rmdir` して拒否（`confine`→`create_dir` 間の中間 symlink すり替え TOCTOU 封じ。
  ファイルの `/proc/self/fd` 再検証と対をなす）。
- **MkDir の `mode` は「作成物だけ」に `clamp_dir_mode` で上限をかけて適用する**: `mode` は
  ピアが選ぶワイヤ値なので、①**自分がこの転送で作成したディレクトリにだけ**（`create_dir` が
  `AlreadyExists` を返したエントリには一切 chmod しない）、②`(mode & 0o0777) & !0o022` に
  丸めて適用する＝**group/other write は必ず落とす**。②が無いと write グラントを持つピアが
  `MkDir{mode:0o777}` で write ルート内に world-writable な置き場を作れ、サーバ上の他の
  ローカルユーザがそこへ書き込める（後からそこにアップロードされるファイルの差し替えを
  含む）。①が無いと同じピアが受信側の保存領域（put ならサーバの write ルート、get なら
  クライアントのローカル保存先）配下の**既存**ディレクトリを狙って `MkDir{path:<既存>, mode:…}`
  を送るだけで、運用者の `0o700` を `0o755` に広げたり、逆に `0o700` へ狭めて運用者の
  グループを締め出せる（get 側の `~/.ssh` がこの形）。この①②は**受信側 2 か所——
  クライアントの `recv_tree`（`get -r`）とサーバの `run_scp_server`（`put -r`）——で同一**。
  よって新規作成される `0o775` / `0o777` のディレクトリはどちら向きの転送でも `0o755` として
  着地し、既存ディレクトリは**どちら向きでも mode が変わらない**（エントリ自体は `Ack`＝
  既存ツリーへの再 put は従来どおり成功し、mode だけが手つかずで残る）。OpenSSH scp は
  逆側の同じトレードで、`-p` 無しではリモート mode を無視する。
- **部分失敗（＝パイプライン下の在庫の運命を明示）**: エントリ毎に `Ack`/`Fail`。confine 拒否・
  stage/commit 失敗は `Fail`（ワイヤは一律 "denied"）で、**サーバはバッチを止めず次のエントリを
  処理し続ける**＝ scp `-r` 互換の「エラーでも続行し最後に集計」。put はパイプライン送信なので
  `Fail` 受信時点で後続は既に in-flight だが、続行方針なのでそのまま処理される（100 中 3 番目
  拒否でも残り 97 は転送）。クライアントは各 `Fail` を `skipped` 表示し `done/total` を報告。監査
  ログには拒否が 1 行ずつ残る（`scp fail: put …` 等）。**致命的エラー**（宣言 size 超過・ファイル
  本文中の想定外フレーム・途中でのストリーム切断）だけはプロトコル違反として `Err`＋ストリーム
  切断でバッチ全体を中断する。per-file 拒否でもファイル本文は宣言 size を上限に消費してストリーム
  同期を保つ。詳細な実測は `P2P_SCP_PIPELINE_REPORT.md`。
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
S: temp へ書き込み。Eof 受信で fsync → fchmod(clamp_file_mode(mode)) → atomic rename(temp→final)。
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
# <sha3-256-hex>  read="root1, root2"  write="root3"   [user=NAME]
a6fc484e...  read="/srv/pub, /home/opc/out"  write="/home/opc/incoming"
```

- `read=` / `write=` は**許可ルート（ディレクトリ）**のカンマ区切り。最低 1 つ必須。
- fingerprint が policy に無ければ全拒否。read ルートに無いパスの Get、write ルートに
  無いパスの Put は Err。
- `user=` は**サーバ自身のユーザを指す時のみ許可**（per-user インスタンスモデル、
  `enforce_scp_user`）。別ユーザ／未知ユーザを指す行は、そのピアのセッションを拒否
  （ワイヤ上は一様に "denied"、理由は監査ログにのみ記録）。上記「やらないこと」参照。
- `mode` は**開いている fd に対して** `fchmod` で適用する。パスベースの
  `set_permissions(temp)` をクローズ後に呼ぶと、temp を symlink にすり替える TOCTOU で
  無関係ファイルを chmod されうるため、fd 経由にして封じる。
- `mode` は**ピアが選ぶワイヤ値**なので、そのままは決して適用しない。`fchmod` は umask で
  フィルタされないため、素通しはピアに「相手ホスト上のファイル権限」を丸ごと渡すのと同じ
  （悪意あるサーバが `--scp-get secret.pem` に `Put{mode:0o666}` で応答すれば、operator の
  鍵が全ローカルユーザから読めて書けるファイルとして着地する）。よって
  `clamp_file_mode` が**下方向のみの上限を 3 段**かける:
  1. `& 0o0777`＝**setuid/setgid/sticky を必ず除去**。アップロード（サーバ側）でも
     ダウンロード（クライアント側）でも、ピアが選んだ権限昇格ビットは決して残らない。
  2. `& !0o022`＝**group/world write を無条件に拒否**。`umask 000` の operator でも、
     他のローカルユーザが中身を差し替えられるファイルは生まれない。
  3. `& !umask`＝**自プロセスが自分で作るファイルより広くならない**。group/other の
     read ビットを決めるのはピアではなく operator の umask になる（`umask 022` なら
     `0o666`→`0o644`、`umask 077` なら `0o600`）。OpenSSH scp も `-p` 無しでは
     リモート mode を無視して local umask に従う。本実装に `-p` 相当は無いので umask が常に勝つ。

  umask は `main` が**tokio ランタイム構築前**（＝まだシングルスレッド）に一度だけ採取して
  `OnceLock` に保持する（`umask(2)` に読み取り専用形が無く、読むこと自体が
  プロセス全体の read-modify-write になるため）。採取されていない場合（ライブラリ埋め込み・
  単体テスト）は最も厳しい `0o077` にフォールバックする＝広い側へ倒れない。
  これら全部を put/get 双方が共有する `Staged::commit` の一点で担保する。

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
