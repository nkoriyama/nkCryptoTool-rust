# 踏み台レス PQC SSH 利用ガイド

nkCryptoTool の P2P シェル／ポートフォワード機能の実用コマンド手順。NAT/CGNAT
配下のホストへ **踏み台なし・ポート開放なし・ポスト量子暗号** で接続する。設計の
詳細は [P2P_SHELL_DESIGN.md](docs/design/P2P_SHELL_DESIGN.md) を参照。

- 相手認証 … アプリ層 ML-DSA-65 チャレンジレスポンス（指紋 = `SHA3-256(署名公開鍵)`）
- 暗号ストリーム … ハイブリッド ECDH‖ML-KEM 由来の AEAD（方向ごと単調カウンタ nonce）
- NAT 越え … iroh（ホールパンチ＋リレー、`--relay-url` 不要）

以下、バイナリ名は `nk-crypto-tool` とする。

---

## 0. 準備 — 鍵生成・指紋・公開鍵交換

各マシンで自分の ML-DSA 署名鍵（＝身元）を生成する。

```bash
# サーバ機・クライアント機それぞれで
nk-crypto-tool --mode pqc --gen-sign-key --key-dir ~/nkkeys --dsa-algo ML-DSA-65
#   → ~/nkkeys/private_sign_pqc.key（秘密・厳重保管）
#     ~/nkkeys/public_sign_pqc.key（公開・相手に渡す）

# 自分の指紋（ポリシー記載や allowlist に使う 32 バイト hex）
nk-crypto-tool --mode pqc --fingerprint --signing-pubkey ~/nkkeys/public_sign_pqc.key
```

**相互認証のため、サーバ⇔クライアントで `public_sign_pqc.key` を事前交換**しておく
（互いにピン留めする）。

> 秘密鍵を暗号化するなら生成前に `NK_PASSPHRASE` を設定する（空なら非暗号）。
> 以降のコマンドで暗号化鍵を使うときは同じ `NK_PASSPHRASE` を与える。

> **鍵リング運用（GPG 風）**: 署名鍵を keyring に置く（`--keyring-cmd gen-my-key
> --key-algo ML-DSA-65` で直接生成、または `import-my-key` で取り込み）なら、
> 本ガイドの**自分側の `--signing-privkey` は以後すべて省略できる** — P2P identity は
> keyring の `sign:<--dsa-algo>` スロットから自動解決される（keyring やスロットが
> 無ければ従来どおり匿名動作）。相手を pin する `--signing-pubkey` は省略できない。
> 詳細は [USAGE.md §0.1 / §5.1](./USAGE.md)。

---

## 1. シェル接続

### サーバ機（待ち受け、ticket を表示）

```bash
nk-crypto-tool --serve-shell --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./client_public_sign_pqc.key      # 許可するクライアントをピン留め
#   → 標準出力に  [nkct] Ticket: nkct1....  と接続用 QR を表示
```

表示された `nkct1....` をクライアントへ渡す（チャット・メール・QR など任意の経路）。

### クライアント機（接続）

```bash
# 対話ログインシェル
nk-crypto-tool --shell --connect 'nkct1....' --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./server_public_sign_pqc.key

# 単発コマンド（ssh host cmd 相当・実行して終了）
nk-crypto-tool --shell-cmd 'systemctl restart app' --connect 'nkct1....' --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./server_public_sign_pqc.key
```

対話シェルは端末を raw mode にし、ウィンドウリサイズ（WINSZ）と終了コードを反映する。

---

## 2. 権限を絞る（ポリシー＋監査）

`shell-policy` ファイル（1 行 = 1 指紋）:

```
# <クライアント指紋 hex>  [user=NAME]  [cmd-allow="c1,c2,..."]
a4d889f8...c00e  user=deploy  cmd-allow="systemctl restart app, journalctl -u app"
```

- `user=` … このセッションを実行するユーザ。**サーバ起動ユーザ自身**しか指定できない
  （Tier 1 はユーザ切替をしない。他ユーザを指すと拒否）。
- `cmd-allow="..."` … 完全一致するコマンドのみ許可（ログインシェルは拒否、ssh の
  `command=` 相当）。Linux では該当セッションのコマンドは `NO_NEW_PRIVS` 付きで
  起動され、許可済みコマンド経由でも setuid/setgid/capabilities による特権昇格が
  カーネルレベルで無効化される（監査ログに `nnp=on`。非 Linux では
  `nnp=unavailable` と記録され、この防御なしで実行される）。

```bash
nk-crypto-tool --serve-shell --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./client_public_sign_pqc.key \
  --shell-policy ./team.shell-policy \
  --audit-log ./shell-audit.log
```

監査ログには `allow`/`deny`/`rate-limit`/`session-end` が時刻＋指紋付きで記録される。

### 実行ユーザと権限（Tier 1：権限降格なし）

シェルは **サーバを起動したユーザ自身** として動く。in-process の権限降格
（setuid/setgid）は行わない（PTY 層を portable-pty に統一した際に setuid 経路を撤去）。
そのため `--serve-shell` は **root で起動すると起動時に拒否される**（全セッションが
root シェルになってしまうため、ポリシーの有無に関わらず弾く）。`--serve-scp` /
`--serve-pairing` も同じ理由で root 起動を拒否する。

- 複数ユーザに serve したい場合は、**ユーザごとに非 root の個別インスタンス**を起動する。
- ポリシーの `user=` は **起動ユーザ自身** のみ指定可（他ユーザへの切替はできない）。
- Windows も、管理者（Administrator）昇格状態での起動は拒否される。

---

## 3. ポートフォワード

### ローカル転送 `-L`（サーバから見えるサービスへトンネル）

サーバ側 `forward-policy`（default deny。`allow=` で接続先を許可）:

```
# <クライアント指紋 hex>  allow="host:port, host2:*, *:443"
ce53fe1b...9cfd  allow="127.0.0.1:5432, db.internal:5432"
```

ホストは **完全一致**（大小無視）か、単独の `*`（全ホスト）のみ。`*.internal` の
ような部分ワイルドカードはどのホストにも一致しない死にルールになるため、
パース時にエラーとして拒否される。ポートは数値の完全一致か `*`。

```bash
# サーバ
nk-crypto-tool --serve-forward --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./client_public_sign_pqc.key \
  --forward-policy ./fwd.policy --audit-log ./fwd-audit.log

# クライアント: ローカル 19090 → サーバ側の 127.0.0.1:5432
nk-crypto-tool --forward 19090:127.0.0.1:5432 --connect 'nkct1....' --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./server_public_sign_pqc.key
#   → 手元で  psql -h 127.0.0.1 -p 19090  などが通る
```

### リモート転送 `-R`（クライアント側サービスをサーバに公開）

サーバ側 `forward-policy` に bind 許可を追加:

```
# allow= と bind= は併記でき、独立に評価される
ce53fe1b...9cfd  allow="..." bind="8080, 9000"
```

```bash
# クライアント: サーバの 127.0.0.1:8080 → クライアント側 127.0.0.1:3000
nk-crypto-tool --remote-forward 8080:127.0.0.1:3000 --connect 'nkct1....' --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./server_public_sign_pqc.key
```

- `--forward` / `--remote-forward` は **複数指定・同時指定**できる。
- 転送ポートはサーバ・クライアントとも **`127.0.0.1` のみ**に bind（off-box 公開なし）。
- 1 接続が多数の TCP を channel として多重化し、チャネルごとに 256 KiB の
  フロー制御窓を持つ（詰まったチャネルが他をブロックしない）。

---

## 4. チーム権限（MLS グループから policy を投影）

メンバーを個別に書く代わりに、**MLS グループのメンバーシップ**からポリシーを生成する。
グループの追加/削除でチームを管理し、再投影でサーバのポリシーを更新する。

```bash
# グループの検証済みメンバーごとに「<指紋>  <テンプレート>」を出力
NK_PASSPHRASE='store-pass' \
nk-crypto-tool --mls-cmd project-policy --mls-group-id <gid> \
  --mls-policy-template 'user=deploy cmd-allow="systemctl restart app"' \
  --signing-privkey ~/nkkeys/private_sign_pqc.key --mls-storage ~/nk-mls.redb \
  > team.shell-policy

# 生成された team.shell-policy を --shell-policy（または --forward-policy）に使う
nk-crypto-tool --serve-shell --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./client_public_sign_pqc.key \
  --shell-policy ./team.shell-policy --audit-log ./shell-audit.log
```

- 投影される指紋は各メンバーの **transport ML-DSA 指紋**（NKCB バインディング検証済み）で、
  シェル／フォワード認可が比較する指紋と一致する。
- バインディングが無効なメンバーは投影されない（自己申告の身元はポリシーに入らない）。
- 認可は **iroh ノード id ではなく ML-DSA 指紋**で行う。
- メンバー管理は `--mls-cmd add-member` / `remove-member`（詳細は
  [CHAT_USAGE_GUIDE.md](CHAT_USAGE_GUIDE.md)）。

---

## セキュリティ上の要点

- **必ず相互ピン留め**: サーバは `--signing-pubkey <client 公開鍵>`、クライアントは
  `--signing-pubkey <server 公開鍵>` を指定する。`--serve-shell` / `--serve-forward` は
  `--allow-unauth` を拒否し、`--keyring-db <db>` か pinned key のいずれかが必須
  （無いと「認証済みなら誰でも」になる）。
- `--keyring-db <db>` … ペアリング（USAGE.md §7）で登録した keyring の **per-service grants** を
  認可に使う（該当 grant が無い peer はサービス接続を拒否）。複数クライアントの認可はこちら。
  `--serve-shell` で `--keyring-db` を使う場合は **`--shell-policy` も必須**（policy なしの
  フル shell は `--signing-pubkey` 単独 pin の時だけ）。
- ピアが shell/forward の ALPN を要求しても、操作者が `--serve-shell` /
  `--serve-forward` で起動していない限りサービスは開かない。
- `--serve-shell` / `--serve-scp` / `--serve-pairing` は **root では起動できない**
  （Tier 1＝権限降格なし。非 root ユーザで、必要ならユーザごとに個別インスタンスを起動）。
- ticket（`nkct1....`）はそのセッションの接続先情報。秘密ではないが、漏れても認可は
  指紋で守られる。

---

## トラブルシュート

- **接続できない**: リレー経由のホールパンチに数秒かかることがある。サーバが ticket を
  表示し、クライアントが `Server authenticated successfully.` を出すか確認する。
- **`--allow-unauth is not permitted ...`**: shell/forward サーバでは禁止。`--keyring-db` か
  `--signing-pubkey` で相手を認可する。
- **`--serve-forward requires --forward-policy`**: フォワードサーバは default deny の
  ポリシーが必須。
- **root で `--serve-shell` が拒否される**: 仕様（Tier 1＝権限降格なし）。シェルを
  持たせたい**非 root ユーザ自身**で `--serve-shell` する。複数ユーザなら各ユーザで
  個別インスタンスを起動する（`--shell-policy` を足しても root では起動できない）。
- **MLS ストレージのパスフレーズ**: `--mls-storage` の redb は非空パスフレーズが必須
  （`NK_PASSPHRASE` を設定）。
