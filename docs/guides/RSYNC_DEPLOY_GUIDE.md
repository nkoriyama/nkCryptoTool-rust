# rsync 連携デプロイガイド（nkct トンネル + 非 root rsyncd）

`--serve-forward` / `--forward` の PQC 相互認証トンネル越しに **非 root の rsync daemon**
へ接続し、`releases/<timestamp>` への同期 + symlink のアトミック切替でデプロイする構成の
運用手順。踏み台なし・ポート開放なしで、`rsync` の同期セマンティクス（mode 保存・冪等な
再実行・`--link-dest` による差分転送）をそのまま使う。

`--serve-scp`（`nkct/scp/3`）が「nkct 自身のファイル転送」であるのに対し、本構成は
**既存の rsync をトンネルに載せる**もの。認可の主体が nkct から rsyncd 側へ移る点が
最大の違いで、本ガイドはその代償の埋め合わせ方を主題とする。

以下、バイナリ名は `nkct` とする。記載の挙動は **rsync 3.4.4 で実測**した
（2026-07-26）。

---

## 0. 構成と脅威モデル

```
[CI / クライアント]                          [デプロイ先サーバ]
  rsync client                                 rsyncd (非 root, address=127.0.0.1)
      │ rsync://127.0.0.1:18730                     ▲ 127.0.0.1:8730
      ▼                                              │
  nkct --forward  ══ PQC P2P トンネル ══>  nkct --serve-forward
      (127.0.0.1 bind)         ML-DSA-65 相互認証         (--forward-policy: default deny)
                               P-256‖ML-KEM-768 AEAD
```

認可は **2 層で別物**である。

| 層 | 認可するもの | 設定 |
|---|---|---|
| nkct | 「この指紋がサーバの `127.0.0.1:8730` へ TCP を張ってよい」まで | `--forward-policy` |
| rsyncd | どのモジュールを読み書きしてよいか | `auth users` + `secrets file` |

**nkct を通ったことは rsyncd には伝わらない**（rsyncd から見た接続元はただの localhost）。
`auth users` を省略すると、トンネルを張れる指紋 = 全モジュール書き込み可になり、さらに
**サーバ上の他のローカルユーザが nkct を通さず直接書き込める**。必ず両方設定する。

### 割り切り（防げないもの）

`releases/` は `deployuser` 所有・書き込み可でなければ rsync が書けない。したがって
**デプロイ鍵（または CI）が侵害された場合、`deployuser` 権限の範囲内での改ざんは防げない**。
サーバ側の setuid 検査・symlink 検査も、swap 後に付け直せる。`--serve-*` の root 拒否原則を
保つ限り原理的に埋まらないので、**防御境界は CI シークレット管理と鍵ローテーション**にある。

サーバ側検証が実際に守るのは「ビルドの事故・パイプラインの欠陥」と「鍵を持たない第三者」まで。

---

## 1. サーバ側のディレクトリ構造と所有権

```text
/data/deploy/                 [root:root 755]
├── bin/                      [root:root 755]   ← deployuser は書き込み不可
│   ├── pre_xfer.sh
│   ├── swap_release.sh
│   └── gc_releases.sh
├── state/                    [deployuser 755]  ← module 外。フック間の受け渡し・マーカー
├── shared/                   [root:root 755]   ← 可変データ（config/ logs/ は deployuser 所有）
├── current -> releases/20260726_130000         ← module 外
└── releases/                 [deployuser 755]  ← rsyncd の module path
    ├── 20260726_120000/
    └── 20260726_130000/
```

**所有権の要点は 2 つある。**

- **`bin/` を `root:root` にする。** フックは `deployuser` 権限で実行されるので、`bin/` が
  `deployuser` に書けると「rsync でフックスクリプト自体を置き換える」＝任意コード実行になる。
- **module path を `releases/` に限定する。** `path = /data/deploy` にすると、クライアントが
  `bin/` も `current` も rsync で触れてしまう。

**`current` を `releases/` の中に置いてはならない。** module 内に置くと、クライアントは
`rsync -a hijack/ rsync://…/app_releases/` を一度流すだけで `current` を任意のリリースへ
付け替えられる（実測で成立）。swap の検証を丸ごと迂回されるため採用できない。

---

## 2. サーバ側の設定

### `rsyncd.conf`

```ini
address = 127.0.0.1          # ← 省略すると 0.0.0.0 と [::] で listen する
port = 8730
use chroot = no              # 非 root 起動では chroot できない
pid file  = /data/deploy/state/rsyncd.pid
log file  = /data/deploy/state/rsyncd.log
lock file = /data/deploy/state/rsyncd.lock

[app_releases]
path          = /data/deploy/releases
read only     = no
auth users    = deployuser
secrets file  = /etc/rsyncd.secrets      # 600
munge symlinks = no                      # §4 の制約を読んでから有効化すること
pre-xfer exec  = /data/deploy/bin/pre_xfer.sh
post-xfer exec = /data/deploy/bin/swap_release.sh
```

デーモンは `deployuser` として起動する（root 起動しない）。

### `forward-policy`（nkct 側・default deny）

```
# <クライアント指紋 sha3-256 hex>  allow="host:port"
1386797e…3240  allow="127.0.0.1:8730"
```

```bash
nkct --serve-forward --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./client_public_sign_pqc.key \
  --forward-policy ./fwd.policy --audit-log ./fwd-audit.log
#   → 標準出力に  [nkct] Ticket: nkct1....
```

---

## 3. クライアント側の手順

```bash
# 1) トンネルを張る（ローカル 18730 → サーバ側 127.0.0.1:8730）
nkct --forward 18730:127.0.0.1:8730 --connect 'nkct1....' --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./server_public_sign_pqc.key &

# 2) トンネルが使えるようになるまで待つ（固定 sleep にしない）
until RSYNC_PASSWORD="$DEPLOY_SECRET" \
      rsync --list-only rsync://deployuser@127.0.0.1:18730/app_releases/ >/dev/null 2>&1; do
  sleep 0.2      # 指数バックオフ推奨。上限は実経路で測って決める（§6）
done

# 3) 本体を新リリースへ同期する
#    --link-dest には「直前のリリース名」を明示する（../current は効かない → §4）
RSYNC_PASSWORD="$DEPLOY_SECRET" rsync -a \
  --link-dest="../20260726_120000" \
  ./build/ \
  rsync://deployuser@127.0.0.1:18730/app_releases/20260726_130000/
```

`--forward` の待ち受けは **`127.0.0.1` 固定**（クライアント・サーバとも off-box 公開なし）。
ただし同一ホストの他ユーザからは見えるので、`auth users` のパスワードは必須。

`RSYNC_PASSWORD` / `--password-file`（`600`）は **PQC 鍵とは別の共有秘密**であり、
ローテーション手順を鍵とは独立に用意すること。

---

## 4. 制約とハマりどころ（すべて実測）

### `--link-dest ../current` は効かない

`--link-dest` の相対パスは **転送先ディレクトリからの相対**に解決される。つまり
`../current` は `<module>/current`（＝ `releases/current`）であって、module 外の
`/data/deploy/current` ではない。

さらに **参照先が存在しなくても警告のみで `exit 0`** になり、**黙って全量転送に劣化する**。

```
rsync: --link-dest arg does not exist: ../current      ← 警告だけ。exit code は 0
```

→ **直前のリリース名を明示する**（`--link-dest=../20260726_120000`）。成功したかは
サーバ側で `stat -c '%h'` が 2 以上（ハードリンク成立）で確認できる。

### 絶対 symlink はモジュールに着地した時点で壊れる

`use chroot = no` のとき、daemon は symlink 値から **先頭 `/` と `..` を除去**する
（`munge symlinks = no` でも起きる。rsyncd.conf(5) の "sanitize paths" 参照）。

| 送った値 | 着地する値 | 可否 |
|---|---|---|
| `libfoo.so.1.2.3`（ツリー内相対） | そのまま | ✅ |
| `../lib/libfoo.so.1`（ツリー内相対） | そのまま | ✅ |
| `/data/deploy/shared/logs` | `data/deploy/shared/logs` | ❌ broken |
| `../../shared/logs` | `shared/logs` | ❌ broken |
| `/etc/passwd`, `../../../../etc/passwd` | `etc/passwd` | ❌ broken（脱出はしない） |

→ **`shared/` への symlink は転送に含めない。** `swap_release.sh` がサーバ側で張る。
→ 副次的に、**symlink escape / `--link-dest=/etc` による module 脱出は成立しない**
（sanitize が主防御として働く）。ただし rsyncd.conf(5) は `munge symlinks = no` +
書き込み可 + chroot off の組み合わせについて「rsync を騙す trick がある」と明記しているため、
サーバ側検証は**多層防御として残す**。

### 可変データを `releases/` の中に置かない

`--link-dest` で作られたファイルは**旧リリースと同一 inode**（ハードリンク）である。
`releases/` 配下を in-place で書き換えると**旧世代まで一緒に変わり、ロールバックが
ロールバックでなくなる**。ログ・設定・アップロードは `shared/` に置くこと。

### `-p`（mode 保存）の範囲

非 root 運用なので **uid/gid は保存できない**（`-o`/`-g` は落ちる）。保存されるのは mode まで。
既存ファイルの mode を変えるには所有者である必要があるため、**同期ユーザを固定する**。

### `--delete` を使わない

毎回新しい `releases/<timestamp>` へ同期するので `--delete` は不要になる。`--delete` の既定は
`--delete-during` で、中断すると「古いものは消えたが新しいものは来ていない」状態が残る。
代わりに**古い世代の掃除は GC スクリプトの責務**になる（削除リスクは消えたのではなく移動した）。

---

## 5. フックの契約

本節のスクリプトは、下表の**実測した環境変数をそのまま与えて実行検証**してある
（正常系の swap、`--link-dest ../current` の拒否、リリース名の traversal 拒否、複数ソース
拒否、`RSYNC_EXIT_STATUS` 非 0 時の非 swap、setuid 検出、範囲外 symlink 検出）。

### 環境変数の可視範囲（rsync 3.4.4）

| 変数 | pre-xfer | post-xfer |
|---|---|---|
| `RSYNC_PID` | ✅ | ✅ **同一値** |
| `RSYNC_REQUEST` | ✅ | ❌ |
| `RSYNC_ARG#` | ✅ | ❌ |
| `RSYNC_EXIT_STATUS` / `RSYNC_RAW_STATUS` | ❌ | ✅ |
| 位置引数 `$@` | 空 | 空 |

**フックに位置引数は渡らない。** すべて環境変数で読む。`RSYNC_PID` が両者で一致するので、
pre での検証結果は `state/pending.$RSYNC_PID` 経由で post へ渡す。

`RSYNC_REQUEST` は `app_releases/20260726_130000/` 形式（モジュール名込み・末尾スラッシュ）。
man 記載どおり複数ソース指定では空白区切りになりうるので、**単一指定を強制する**。

### `pre_xfer.sh` — 引数検証（転送前に拒否できる）

`--link-dest` は **`--link-dest` と値の 2 つに分割**されて届く。`--link-dest=*` の
パターンマッチでは検出できない。

```
RSYNC_ARG0=rsyncd  ARG1=--server  ARG2=-logDtpre.iLsfxCIvu
ARG3=--link-dest   ARG4=../20260726_120000   ARG5=.   ARG6=20260726_130000/
```

```bash
#!/usr/bin/env bash
set -euo pipefail
STATE=/data/deploy/state

# 要求は単一・リリース名の形式のみ
REQ="${RSYNC_REQUEST:?}"
[[ "$REQ" != *' '* ]]        || { echo "multiple source paths are not allowed"; exit 1; }
RELEASE=$(basename "$REQ")
[[ "$RELEASE" =~ ^[0-9]{8}_[0-9]{6}$ ]] || { echo "bad release name: $RELEASE"; exit 1; }

# --link-dest は「../<リリース名>」のみ許可（値は次の ARG に入る）
i=0; prev=""
while var="RSYNC_ARG$i"; [[ -n "${!var+x}" ]]; do
    arg="${!var}"
    if [[ "$prev" == "--link-dest" ]]; then
        [[ "$arg" =~ ^\.\./[0-9]{8}_[0-9]{6}$ ]] || { echo "bad --link-dest: $arg"; exit 1; }
    fi
    prev="$arg"; i=$((i+1))
done

printf '%s\n' "$RELEASE" > "$STATE/pending.${RSYNC_PID}"
```

**pre-xfer の stdout はクライアント端末に表示される。** 拒否理由を伝えられるのはここだけで
（post-xfer の stderr は届かない）、非ゼロ終了で転送は開始前に中止され、宛先ディレクトリも
作られない。クライアントは `exit 4` を受け取る。

### `swap_release.sh` — 検証と切替

```bash
#!/usr/bin/env bash
set -euo pipefail
STATE=/data/deploy/state
PENDING="$STATE/pending.${RSYNC_PID:?}"

# post-xfer は pre-xfer が拒否した転送でも実行される（そのとき EXIT_STATUS は非 0）
if [[ "${RSYNC_EXIT_STATUS:-1}" -ne 0 ]]; then
    rm -f "$PENDING"; exit 0
fi
[[ -f "$PENDING" ]] || exit 0            # pre-xfer を通っていない転送は無視
RELEASE=$(<"$PENDING"); rm -f "$PENDING"
TARGET="/data/deploy/releases/$RELEASE"

exec 200>/data/deploy/state/deploy.lock  # GC と共用のロック
flock -n 200 || { echo "another deploy/GC in progress" >&2; exit 1; }

# setuid/setgid の混入を拒否
find "$TARGET" -type f -perm /6000 | grep -q . && { echo "setuid detected" >&2; exit 1; }

# symlink の参照先を許可リストで縛る（境界に / を付けて兄弟ディレクトリを弾く）
while IFS= read -r -d '' link; do
    t=$(readlink -f "$link" || true)
    case "$t" in
        "$TARGET"|"$TARGET"/*|/data/deploy/shared|/data/deploy/shared/*) ;;
        *) echo "symlink out of bounds: $link -> $t" >&2; exit 1 ;;
    esac
done < <(find "$TARGET" -type l -print0)

# shared/ への参照はサーバ側で張る（転送には含めない → §4）
ln -sfn /data/deploy/shared/config "$TARGET/config"
ln -sfn /data/deploy/shared/logs   "$TARGET/logs"

touch "$STATE/${RELEASE}.deployed"       # GC の判定材料。module 外に置く

# アトミック切替: ln -sfn は unlink→symlink で非アトミックなので必ず rename(2) を使う
ln -sfn "$TARGET" /data/deploy/current.tmp
mv -Tf  /data/deploy/current.tmp /data/deploy/current
```

**`ln -sfn` 単体で `current` を差し替えないこと。** 既存を unlink してから作り直すため、
参照側が ENOENT を踏む窓がある。`mv -T`（`rename(2)`）はアトミックに置換する。

### 転送完了の判定について

push 方向では、クライアント側の異常は `RSYNC_EXIT_STATUS` に伝わる（実測: SIGKILL → 12、
クライアント側 read error → 23、pre-xfer 拒否 → 4）。したがって
**「サーバ側 exit status が 0」を swap の前提にしてよい**。

ただし rsyncd.conf(5) には「クライアント側で起きたエラーはサーバに送られないので、これは
転送全体の最終ステータスではない」という但し書きがあり、push 方向で再現条件を見つけられて
いないだけである。より強く保証したい場合は、本体転送では swap せず、**クライアントが自分の
終了コードを確認してから `<release>.commit` を別モジュールへ送り、その post-xfer で swap する**
2 段階コミットにする。

### `gc_releases.sh` に必要なもの

- **同じ `deploy.lock` で `flock` を取る**（`readlink current` と `rm -rf` の間に swap が
  走ると、`current` になったばかりのディレクトリを消す）。
- 削除対象は `state/<release>.deployed` があり、かつ `current` の参照先でも
  `--link-dest` の基準でもない世代に限る。
- マーカーの無い世代（＝失敗した転送。**空の宛先ディレクトリが残る**ことを実測）は
  mtime が十分古いものだけを掃除する（進行中の転送先を消さないため）。
- 削除パスは `^/data/deploy/releases/[0-9]{8}_[0-9]{6}$` で厳格に検証する。

---

## 6. 接続時間について

同一ホスト（direct パス）で、`--forward` 起動から `rsync --list-only` が通るまで
**約 0.41 秒**だった（3 回とも 0.412〜0.415s、計測粒度 0.1s）。

**relay 経由は未測定。** バックオフの上限をこの数字から決めないこと。実際の相手ホストとの
間で測ってから決める。固定 `sleep` は経路が変わると必ず壊れる。

---

## 関連

- [`P2P_SSH_USAGE_GUIDE.md`](./P2P_SSH_USAGE_GUIDE.md) — 鍵生成・指紋・`--forward` の基本
- [`P2P_SCP_DESIGN.md`](../design/P2P_SCP_DESIGN.md) — nkct 自身のファイル転送（`nkct/scp/3`）
- [`SECURITY.md`](../../SECURITY.md) — 脅威モデルと運用ベストプラクティス
