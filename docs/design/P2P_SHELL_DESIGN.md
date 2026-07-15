<!--
  設計メモ（草案）: nkCryptoTool をベースにした P2P シェル（"踏み台レス SSH" 相当）。
  実装着手前のレビュー用。確定ではない。関連: SPEC.md, CHAT_USAGE_GUIDE.md,
  MLS_P2P_SYNC_DESIGN.md（撤回済み機能の教訓含む）, project memory
  project_p2p_transport_demo_findings。
-->

# 設計メモ: P2P シェル（踏み台レス・PQC SSH 相当）

## 0. 一行で

iroh の NAT 越え＋既存の PQC 相互認証ストリームの上に **リモート PTY/シェル** を載せ、
NAT 配下のホストへ **踏み台なし・ポート開放なし・ポスト量子安全** でシェル接続できるようにする。

## 1. 目的 / 非目的

**目的**
- NAT/CGNAT 配下のホストに、inbound ポート開放も踏み台も無しで対話シェル接続する。
- 接続相手を**暗号的に相互認証**（PQC）し、許可された peer だけがシェルを得る。
- セッションは end-to-end 暗号（リレーは暗号文＋メタデータのみ）。

**非目的（少なくとも v1）**
- OpenSSH の完全代替（sftp/scp/rsync-over-ssh, ProxyJump, agent forwarding, ~/.ssh/config 互換は対象外）。
- 多ユーザ PAM 連携・対話パスワード認証（鍵/指紋ベースのみ）。
- Windows サーバ側（クライアントは可）。ConPTY 対応は後段。

## 2. 脅威モデル

- **守る**: セッションの機密性・完全性・相手認証（能動 MITM 含む）。未認可 peer によるシェル取得の拒否。
  リレー運営者・経路上攻撃者からの内容秘匿。
- **守らない（前提）**: サーバ OS 自体の侵害、ローカル root、許可済み peer の正当な操作の悪用
  （= SSH と同じく「鍵を持つ正規ユーザ」は信頼）。メタデータ（誰がいつ繋いだか）はリレーに見える
  （自前リレーで緩和）。
- **最重要原則**: 「リモートでシェルを起こす」=最高価値の攻撃面。**認証が一点でも緩いと即致命**。
  既定は deny、allowlist 必須、認可は明示的ホワイトリスト。

## 3. 再利用する既存基盤（新規実装を最小化）

| 必要なもの | 既存実装 | 場所 |
| :-- | :-- | :-- |
| NAT 越え transport | iroh holepunch＋relay（ticket に relay 埋込済み） | `src/p2p/backend/iroh.rs` |
| 相互認証 | アプリ層 ML-DSA-65 チャレンジレスポンス → `PeerId::Pubkey(SHA3-256(ML-DSA pub))` | `src/p2p/processor.rs:295-344` |
| アクセス制御 | `cached_allowlist`（SHA3-256 指紋集合）で照合、未登録は拒否 | `src/p2p/processor.rs:333` |
| 暗号双方向ストリーム | ハイブリッド ECDH‖ML-KEM セッション鍵＋AEAD、`chat_loop` の全二重バイト流 | `src/network/mod.rs`（chat_loop） |
| 安定 ID / 到達情報 | `node.key`（永続 NodeId）＋ ticket | iroh.rs `load_or_create_node_secret`, `src/ticket.rs` |

→ **新規に作るのは「PTY ブリッジ」「認可ポリシー」「監査ログ」「（任意）ポートフォワード」だけ**。
   transport と鍵交換と相手認証は流用する。

## 4. アーキテクチャ

新しい ALPN を 1 本足す: `ALPN_SHELL = b"nkct/shell/1"`（`src/network/mod.rs` の ALPN 群に追加）。
chat とは別経路にして、shell サーバは shell ALPN だけを受ける。

```
client                              server (--serve-shell)
  connect(ALPN_SHELL) ──────────────▶ accept
  ── PQC handshake（既存：相手の指紋を相互認証）──
  [server] 指紋を authz ポリシーで照合 → 許可ユーザ/シェル決定（不許可なら即 close + 監査ログ）
  ── 全二重暗号ストリーム確立 ──
  [client] 端末を raw 化、ローカル端末サイズ送信
  [server] openpty + 当該ユーザのシェルを fork/exec、PTY master を stream に橋渡し
  <stdin keystrokes> ──────────────▶ PTY master write
  PTY master read ◀────────────────── <stdout/stderr>
  SIGWINCH → WindowSize フレーム ───▶ ioctl(TIOCSWINSZ)
  シェル終了 → Exit{code} フレーム ──▶ client 復帰、端末復元
```

## 5. ワイヤプロトコル（ALPN_SHELL の上、handshake 後）

セッション鍵で暗号化された AEAD ストリーム上に、型付きフレームを流す（len 前置）。

```text
フレーム = type(1) ‖ len(u32 BE) ‖ payload
type:
  0x01 OPEN     payload = cols(u16) ‖ rows(u16) ‖ term_len(u16) ‖ TERM ‖ cmd_len(u16) ‖ cmd
                cmd 空 = ログインシェル。cmd 指定 = 単発コマンド（authz が許す場合のみ）。
  0x02 DATA     payload = 端末バイト列（双方向。client→server=stdin, server→client=stdout/err 混合）
  0x03 WINSZ    payload = cols(u16) ‖ rows(u16)（SIGWINCH 反映）
  0x04 EXIT     payload = exit_code(i32 BE)（server→client、シェル終了）
  0x05 ERROR    payload = utf8 メッセージ（authz 拒否・spawn 失敗等）
```
- OPEN は handshake 直後に client が 1 度だけ送る。server は authz 判定 → OK なら PTY 起動、NG なら ERROR+close。
- フレーム上限（例 1 MiB）と OPEN の cols/rows/長さ境界を厳格チェック（既存 MAX_*_FRAME と同様の防御）。

## 6. 認可モデル（最重要）

**既定 deny。** allowlist（現行は redb keyring の allowlist テーブル＝`--keyring-db`。設計当時は平文 `--peer-allowlist`、後に廃止）に無い指紋は handshake で拒否（既存挙動）。
その上に **shell 専用の認可マップ**を足す:

```text
# shell-policy ファイル（例。1行 = 指紋 → 許可)
<sha3-256 指紋hex>  user=alice           # ログインシェルを alice として許可
<sha3-256 指紋hex>  user=deploy cmd-allow="systemctl restart myapp,journalctl -u myapp"
```
- 指紋 → ローカルユーザのマッピングは**明示的にのみ**。マップに無ければシェル不可。
- `cmd-allow` 指定時は単発コマンドのみ（OPEN の cmd がホワイトリストに一致した時だけ exec）。
- **権限分離**: shell サーバ本体は最小権限デーモンとして動き、PTY/シェルは対象ユーザに
  `setuid`/`setgid`（+ supplementary groups）で降格してから exec。root シェルは既定で不許可
  （明示 opt-in＋警告）。
- **監査ログ**: 接続元指紋・解決ユーザ・OPEN(cmd/ログイン)・開始/終了時刻・exit code を追記専用ログへ。
- **レート制限**: 指紋ごとの接続試行/失敗にバックオフ（既存 PEER_COOLDOWNS の発想を流用）。

## 7. CLI 表面（案）

```bash
# サーバ（常駐。allowlist と shell-policy 必須）
nk-crypto-tool --serve-shell \
  --signing-privkey host_sign.key \
  --keyring-db keyring.db \
  --shell-policy shell-policy.txt \
  --audit-log /var/log/nkct-shell.log
# 起動時に自分の ticket を表示（クライアントに渡す）

# クライアント（対話シェル）
nk-crypto-tool --shell --connect <server-ticket> \
  --signing-privkey my_sign.key --signing-pubkey host_pub.key

# 単発コマンド
nk-crypto-tool --shell --connect <server-ticket> ... -- systemctl restart myapp
```
- サーバ側 `--signing-pubkey`（クライアント公開鍵ピン）or `--keyring-db` で相手認証（既存と同形）。
- クライアントは `--signing-pubkey`（サーバ公開鍵ピン）で MITM 防止（chat と同じ作法）。

## 8. PTY 実装メモ

- crate: `portable-pty`（openpty 抽象、将来 ConPTY も）。または unix 限定で `nix`＋`libc` 直叩き。
- 子プロセス: `fork`→（降格 setuid/setgid）→`execve(shell, ["-l"])`、環境を最小化（PATH/TERM/HOME 設定、
  危険な環境変数は除去）。PTY master を非ブロッキングで read/write。
- ウィンドウサイズ: WINSZ フレーム → `ioctl(TIOCSWINSZ)`。
- クライアント端末: raw mode（`termios`）、終了時に必ず復元（パニック時も）。
- 既存の `chat_loop`（全二重 select ループ＋AEAD）の構造を雛形に流用できる。

## 9. 段階実装計画

- **Phase 0**: ALPN_SHELL 追加、handshake 後にフレーム型＋ echo サーバ（PTY 無し、認可は allowlist のみ）で
  ストリーム/フレーミングを検証。
- **Phase 1**: 単一ユーザ PTY ブリッジ（サーバ起動ユーザのシェルをそのまま起動）。raw 端末・WINSZ・EXIT。
  allowlist 必須。**まだ降格・cmd-allow 無し**＝信頼済み単一ユーザ前提。実機（rustdev/nkwire）で対話確認。
- **Phase 2** ✅: 認可ポリシー（指紋→user マップ）＋権限分離（setuid 降格）＋監査ログ＋レート制限。
  実装は 2a（authz/cmd-allow/audit/rate-limit）＋2b（setuid 権限分離・自前 openpty）に分割済み。
  ※ 当初 Phase 3 とした「単発コマンド（cmd-allow）」は 2a に取り込み済み。
- **Phase 3**（実装名、当初 Phase 4）✅: ポートフォワード（local `-L`、チャネル多重化）。`src/forward.rs`、
  ALPN `nkct/fwd/1`。1 接続が多数の TCP を channel として多重化。サーバは fingerprint→`host:port` 許可ポリシー
  （default deny）で onward 接続を制御＋監査。`--serve-forward`/`--forward-policy`（サーバ）、
  `--forward localport:host:remoteport`（クライアント、反復可）。remote `-R` は未実装。
- **Phase 4（任意）** ✅: remote forward（`-R`）。クライアントが `--remote-forward bindport:host:destport` で
  サーバに bind を要求、サーバの 127.0.0.1:bindport への接続をトンネル経由でクライアント側 `host:destport` へ戻す。
  ポリシーに `bind="port,..."` を追加（default deny）。チャネル ID は originator で範囲分離（client 1.., server 0x8000_0000..）。
- **Phase 5（任意）** ✅: per-channel フロー制御（SSH 風 credit window）。各方向 256KiB のバイト窓。送信側はクレジット
  分だけ先行送信し、受信側は TCP へ書き出した分を `WindowAdjust` で補充。受信キューは bounded（demux は try_send で
  非ブロッキング、満杯＝違反で切断）。これで 1 つの詰まったチャネルが他チャネルや制御フレームを HoL ブロックしない。
- **Phase 6（実装名、当初 Phase 5）** ✅: MLS グループでチーム権限（メンバーシップを shell/forward ポリシーに**投影**）。
  `--mls-cmd project-policy --mls-group-id <gid> --mls-policy-template '<attrs>'` が、グループの**バインディング検証済み**
  メンバーごとに `<transport指紋hex>  <attrs>` 行を出力。サーバはそれを既存の `--shell-policy`/`--forward-policy` として使う。
  メンバー追加/削除は MLS 側で行い、再投影でポリシー更新。**認可は ML-DSA 指紋（NKCB の transport_pub = handshake 署名鍵、
  `SHA3-256` が shell/forward 指紋と一致）で行い、iroh ノード id では gate しない**（過去の撤回の教訓を順守）。
  ※ 過去の「MLS↔transport 投影（node id gate）」は層の取り違えで撤回（[MLS_P2P_SYNC_DESIGN.md]）。本 Phase は指紋層で実装。

## 10. セキュリティ考慮（チェックリスト）

- [ ] 既定 deny。allowlist 未設定で `--serve-shell` 起動はエラー（`--allow-unauth` 相当は **禁止**）。
- [ ] handshake の指紋検証は既存経路を流用（自前で再実装しない）。過去 TCP transport の認証バグ（transcript
      不一致）の教訓：認証ロジックは新規に書かない。
- [ ] 権限分離・setuid 降格・root シェル既定禁止。
- [ ] 監査ログ（追記専用、指紋/ユーザ/コマンド/時刻/exit）。
- [ ] フレーム長・OPEN 境界・cols/rows の厳格バリデーション、idle/handshake タイムアウト。
- [ ] レート制限／バックオフ。
- [ ] 子プロセス環境の最小化（環境変数除去、PATH 固定）。
- [ ] クライアント端末 raw mode の確実な復元（Drop ガード）。
- [ ] メタデータ秘匿が要る運用は自前リレー。

## 11. 未決事項（着手前に確定）

1. PTY 経路は **既存 NetworkProcessor handshake を流用**（推奨）か、shell 専用に薄く再構成か。
   → 流用が安全（認証を再発明しない）。要：`run_listen`/`run_connect` を chat/file 同様に shell へ分岐させる設計。
2. 認可マップのフォーマットと配置（ファイル？将来 redb？）。v1 はプレーンファイルで十分。
3. 権限分離の実装範囲（setuid のみ？ namespaces/seccomp までやるか）。v1 は setuid 降格＋環境最小化、
   サンドボックス強化は後段。
4. 単発コマンドの引数解釈（シェル経由か execve 直か）。インジェクション回避のため execve 直＋完全一致推奨。

## 12. テスト計画

- 単体: フレーム encode/decode 境界、authz マップ解決、cmd-allow 一致/不一致、端末サイズ反映。
- E2E（mock transport）: handshake→OPEN→DATA echo→EXIT。未認可指紋の拒否。
- 実機: rustdev（x64）・nkwire（arm64）へ bazzite から踏み台なしシェル接続、対話・WINSZ・exit code、
  未許可指紋拒否、監査ログ確認。

---

**結論**: transport/鍵交換/相手認証が再利用できるため MVP は現実的。価値が一番出るのは
「到達性のために踏み台を踏んでいた」環境（NAT/CGNAT 配下ホスト）。ただしリモートシェルは攻撃面が
最大級なので、**認可・権限分離・監査を Phase 2 で堅牢化するまでは「信頼済み単一ユーザ＋allowlist 必須」
に限定**して進めるのが安全。Tailscale SSH が同コンセプトを実証済み（差別化は PQC ネイティブ＋自己完結）。
