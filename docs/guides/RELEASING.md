# リリース規約と手順

nkct を crates.io と GitHub Releases に出すときの決まりと手順。

この文書は 2.2.1 の初回公開で実際に踏んだ手順と失敗をそのまま規約にしたもの。
「なぜこうするのか」の根拠は末尾の[不変条件](#不変条件なぜこの手順なのか)にある。
手順だけ必要なら[リリース手順](#リリース手順)へ。

---

## バージョン番号の意味

**この repo では crate のバージョンは「互換性の契約」ではない。**

lib ターゲット（`rlib` / `cdylib`）は bin とモバイル FFI シムのために存在するもので、
**公開 API ではない**（`Cargo.toml` に明記）。利用者が触れるのは CLI と、**通信相手**。

そして本当の互換性の面は、すでに独立してバージョニングされている:

```
nkct/chat/2   nkct/file/3   nkct/fwd/2    nkct/inbox/1
nkct/mls/1    nkct/pairing/1  nkct/scp/3  nkct/shell/2
```

ALPN の番号がプロトコル互換性を担う。crate のバージョンにそれを背負わせない。

crate のバージョンの仕事は「利用者が何を動かしているか」「手元より新しいか」を伝えること。
基準は Rust API ではなく、**利用者のデータと通信相手**:

| | 条件 |
|---|---|
| **MAJOR** | 既存の鍵・暗号ファイル・DB が読めなくなる、または旧版と P2P できなくなる |
| **MINOR** | 機能追加、CLI フラグ追加、後方互換なプロトコル拡張 |
| **PATCH** | 修正のみ。CLI フラグもファイル形式も ALPN も不変 |

CLI の破壊的変更（フラグの削除・改名、実行ファイル名の変更）は MAJOR に当たる。
2.2.0 での `nk-crypto-tool` → `nkct` はこれだが、crates.io 公開前だったので実害はなかった。

---

## いつ出すか

**溜めない。** パイプラインが自動化された今、1 回のリリースは CI 25 分と承認クリック 1 回。
溜めるコストの方が高い。

実績: v2.1.0 から v2.2.1 まで **3 か月半・338 コミット・60 PR** 空いた。その結果、
CHANGELOG を 60 PR から再構成する羽目になり、`Cargo.toml` のバージョンは 3 か月半
古いままだった（mandate ゲートがそれを検出して 2.2.0 の CI を落とした）。

利用者が欲しがるものが入ったら出す、で十分。

---

## CHANGELOG の運用

**`## [Unreleased]` を常設し、変更した PR の中で書く。**

これが最も効く習慣。2.2.0 のエントリを 60 PR から再構成した経験がその根拠。
リリース時は `[Unreleased]` を `[X.Y.Z] - YYYY-MM-DD` に書き換えるだけにする。

---

## rc を使う基準

**リリースの機構が変わるときだけ。** 成果物の追加、対応プラットフォームの追加、
`release.yml` や `reproducible-build.sh` の変更がこれに当たる。
通常の機能リリース・修正リリースには不要。

根拠: 2.2.0 で使った rc は 2 本とも**機構のバグ**を捕まえた。製品のバグではない。

- `rc.1` — guard の同梱ファイル検査が、リストを checkout 内に書いて作業ツリーを汚し、
  `cargo package` が dirty なツリーを拒否した。**コマンドが自分の前提を壊していた**
- `rc.2` — macOS の Gatekeeper。ブラウザで落とすと quarantine が付き、ダイアログの
  選択肢は「ゴミ箱に入れる」と「完了」だけ。`curl` では再現しないので、
  **ターミナルだけで試していたら永久に気づけなかった**

rc も `Cargo.toml` のバージョンとタグを一致させる（`2.2.0-rc.1` / `v2.2.0-rc.1`）。
guard がタグと manifest の一致を要求するため。

---

## 前提（一度だけ）

1. **crates.io の API トークン** — https://crates.io/settings/tokens
   - 初回公開には `publish-new` が必要（`publish-update` だけでは新規 crate を作れない）
   - Crate scope を `nkct` に絞る。`yank` / `change-owners` は外す
   - 期限は付ける（無期限にしない）。切れると publish ジョブが 401 で落ちる
2. **アカウントのメールアドレスを verify する** — https://crates.io/settings/profile
   未確認だと publish が 400 で落ちる（2.2.1 で踏んだ）
3. **GitHub Secret** — `gh secret set CRATES_IO_TOKEN`。名前はこれで固定（`release.yml` が参照）
4. **`crates-io` Environment** — Settings → Environments
   - Required reviewers に自分を追加
   - **Prevent self-review は OFF**（ON にすると承認者が存在しなくなり永久に止まる）
   - **Allow administrators to bypass は OFF**（ON だとゲートの意味が消える）
   - Deployment tags を `v*` に

---

## リリース手順

### 1. リリース PR

- `Cargo.toml` のバージョンを上げる
- `CHANGELOG.md` の `[Unreleased]` を `[X.Y.Z] - YYYY-MM-DD` にする
- **`scripts/mandate_check.sh` のバージョン許容値を一緒に動かす**
  （`RELEASE_MODE` 側と dev 側の 2 か所、および premature タグの正規表現）
- ローカルで `bash scripts/mandate_check.sh` が通ることを確認

### 2. CI が緑になったらマージ

1 つでも赤があればマージしない。`continue-on-error` のステップは
**失敗しても API 上 `conclusion: success` と報告される**ので、そういうジョブは
結論ではなくログで確認する。

### 3. タグを打つ

```bash
git checkout main && git fetch origin main && git reset --hard origin/main
# HEAD == origin/main と、作業ツリーがクリーンなことを確認してから
git tag -a vX.Y.Z -m "vX.Y.Z ..."
git push origin vX.Y.Z
```

### 4. パイプラインが走る（約 25 分）

タグ push で `release.yml` が起動する。各ジョブが見ているもの:

| ジョブ | 検査 |
|---|---|
| **guard** | タグと `Cargo.toml` の一致 / `cargo publish --dry-run --locked` / 同梱ファイル検査（フロア付き） |
| **linux-musl** | 独立した `--no-cache` コンテナビルド ×2 のバイト一致 → **成果物を起動して P2P 往復** |
| **linux-musl-arm64** | 同上（arm64 ランナー、arm64 用に digest 固定した別 Containerfile） |
| **macos** | 両 Apple ターゲット + `lipo` → **universal バイナリを起動して P2P 往復** |
| **windows** | cargo-xwin クロスビルド（実機テストは `ci.yml` の `test-windows` が担当） |
| **release** | GitHub Release 作成。タグに `-` があれば pre-release |
| **publish** | **`crates-io` Environment の承認待ちで停止** |

**GitHub Release は承認の前に作られる。** つまり承認前に成果物をダウンロードして
実機で確かめられる。これは意図した順序。

### 5. 承認前に確認する

```bash
gh release view vX.Y.Z --json assets --jq '.assets[] | "\(.size)  \(.name)"'
gh release download vX.Y.Z -p SHA256SUMS -D /tmp/rel && cat /tmp/rel/SHA256SUMS
```

ログで実測を確認する（ジョブの結論ではなく）:

```bash
RUN=<run id>
gh api "repos/nkoriyama/nkCryptoTool-rust/actions/runs/$RUN/jobs" \
  --jq '.jobs[] | select(.name|test("musl|macOS")) | .id' | while read ID; do
  gh api "repos/nkoriyama/nkCryptoTool-rust/actions/jobs/$ID/logs" \
    | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -E 'build A:|build B:|OK: reproducible|P2P smoke OK'
done
```

- 再現ビルドの A と B が一致し、公開ハッシュとも一致しているか
- 3 ジョブの P2P smoke がすべて通ったか

実機がある場合はここで踏む（[実機での確認](#実機での確認)）。

### 6. 承認する

Actions の該当 run → Review deployments → `crates-io` → Approve and deploy。

**タグ名を確認してから押す。** `-rc` が付いていないこと。承認は取り消せない。

コメント欄（任意、履歴に残る）の例:

```
Reproducible builds match published hashes; all artifacts passed a real
iroh P2P round-trip, including the arm64 binary on a Raspberry Pi 4.
```

### 7. 公開後の確認

```bash
curl -s https://crates.io/api/v1/crates/nkct | jq '.crate.max_version'
cargo install nkct --locked --root /tmp/install-check && /tmp/install-check/bin/nkct --version
```

---

## 実機での確認

CI では原理的に答えられないことがある。手元に実機があるなら承認前に踏む。

**arm64 Linux（Raspberry Pi）** — GitHub の `ubuntu-24.04-arm` ランナーは
サーバ級で **ARMv8 Crypto Extensions を持つ**。Pi は持たない。CPU フロアを
間違えても CI は緑のまま Pi でだけ SIGILL するので、ここは実機でしか分からない。

```bash
curl -sSL -o /tmp/nkct https://github.com/nkoriyama/nkCryptoTool-rust/releases/download/vX.Y.Z/nkct-vX.Y.Z-aarch64-unknown-linux-musl
chmod +x /tmp/nkct && sha256sum /tmp/nkct   # 公開値と照合
bash ci/artifact_p2p_smoke.sh /tmp/nkct     # P2P まで通す
```

**macOS** — **必ずブラウザでダウンロードする。** `curl` や `gh release download`
では quarantine 属性が付かず、利用者が実際に見る挙動を再現できない。
Gatekeeper に止められることを確認したら `xattr -d com.apple.quarantine <file>` で解除。

---

## 失敗したときの戻し方

| 状況 | 対処 |
|---|---|
| guard やビルドで落ちた | GitHub Release も publish も作られていない。修正 PR → マージ → **タグを削除して打ち直す**（`git push origin :refs/tags/vX.Y.Z` → 再作成）。何も公開していないので番号は消費されない |
| Release は作られたが承認前に問題が見つかった | `gh run cancel <run id>` で止める。`gh release delete vX.Y.Z --cleanup-tag` でリリースとタグを消す。crates.io は未消費 |
| publish がアカウント都合で落ちた（メール未確認・トークン期限切れ） | 原因を直して `gh run rerun <run id> --failed`。承認ゲートを再度通る |
| **publish が成功した後に問題が見つかった** | **バージョンは取り消せない。** `cargo yank --version X.Y.Z` は「新規の依存解決に使われなくする」だけで削除ではない。次の PATCH を出す |

**タグの再利用は「何も公開していないとき」に限る。** GitHub Release が作られたり
crates.io に出た後は、番号を進める。

---

## 不変条件（なぜこの手順なのか）

以下はすべて 2.2.0 の失敗から来ている。手順を変えるときはこれらを壊していないか確認する。

**1. ビルドできることは、動くことではない。**

2.2.0 の musl 成果物は `cargo package`・再現ビルドのバイト一致・公開ハッシュ照合・
`--version`・実機での ML-KEM 鍵生成・KeyBundle 署名・AES-GCM と ChaCha20 の暗号往復・
改竄検出を**すべて通り**、P2P が一切できなかった。`noq-udp` が `SO_TIMESTAMPNS` の
制御メッセージを glibc 前提のアライメントで読むため、musl では最初の 1 パケットで
abort する（[n0-computer/noq#774](https://github.com/n0-computer/noq/issues/774)）。

**通ったどの検査もソケットを開かなかった。** だから `ci/artifact_p2p_smoke.sh` がある。
成果物を起動し、iroh 越しにリモートコマンドの出力が返ることを要求する。
**新しい成果物を追加したら、その smoke も追加する。**

**2. テストする構成と配る構成を一致させる。**

`ci.yml` のテストは **gnu** ビルドで走る。musl バイナリはコンテナ内で作られるだけで
実行されていなかった。その隙間から 1 が出た。

**3. `continue-on-error` のステップは、失敗しても `conclusion: success` になる。**

macOS と arm64 のジョブを advisory で導入したとき、2 度これに騙された。
成果物を配るプラットフォームの CI ジョブは release-blocking にする。

**4. `RUSTFLAGS` はジョブ単位で設定する。ワークフロー全体に置かない。**

`RUSTFLAGS` は `[target.*].rustflags` を**置き換える**（追加ではない）。しかも
**空文字でも「設定された」と見なされる**ので `RUSTFLAGS: ""` は opt-out にならない。
ワークフロー全体に置くと、`.cargo/config.toml` が各ターゲットに与えている可搬 CPU
フロアが丸ごと消える。

**5. CPU フロアは非対称。**

x86 は `+aes,+pclmulqdq` を**要求する**（AES-NI は x86-64-v2 で普遍）。
aarch64 は**要求してはならない**（ARMv8 Crypto Extensions は任意実装で、Pi にない）。
間違う方向は片方だけ：拡張を要求すると持たない機械で SIGILL、要求しなければ
持つ機械でも動く（遅いだけ）。

**6. 検査を追加したら、良品と不良品の両方で試す。**

`artifact_p2p_smoke.sh` は、修正版バイナリで通り、公開済みの壊れた `v2.2.0-rc.2` で
落ちることを確認してから配線した。片方だけでは、その検査が何かを検出できる証拠にならない。

**7. 検査は自分の前提を壊してはいけない。**

guard の同梱ファイル検査は、リストを checkout 内に書き出して作業ツリーを汚し、
`cargo package` に拒否された。出力先は `RUNNER_TEMP` に置く。

**8. 空振りする検査は「合格」に見える。**

`cargo package --list` が失敗すると空のファイルが残り、それを grep しても禁止パスは
見つからない。だから同梱ファイル検査には**フロア**（150 前後あるはずのファイル数が
100 未満なら異常）がある。同じ形の fail-open は
`scripts/check_security_baseline.sh` にもある（F2）。
