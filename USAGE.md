# USAGE — ユースケース別クックブック

やりたいこと別に「こう打てばできる」をまとめた実用ガイド。設計背景は各 DESIGN ドキュメント、
機能一覧・性能・アーキテクチャは [README](./README.md) を参照。ここはコマンドだけ。

- コマンドは `nk-crypto-tool`（ビルド後は `target/release/nk-crypto-tool`）。
- `--mode` は `pqc`（ML-KEM/ML-DSA、既定推奨）/ `ecc`（P-256）/ `hybrid`（PQC＋古典の二重）。
- 秘密鍵のパスフレーズは既定で対話入力。自動化は `NK_PASSPHRASE` 環境変数（警告が出る）。
- `--key-dir <dir>` は鍵を**規約ファイル名**（`private_sign_pqc.key` / `public_enc_pqc.key` 等）で
  自動的に探す。`/` や `./` を含む明示パスを渡した場合はそのまま使う。
- ここでの例は `--mode pqc` を基準にする。ecc / hybrid はファイル名とフラグが少し変わる（各節で明記）。

> **指紋（64-hex）は 1 個だけ。** この後ずっと出てくる 64 桁の 16 進は、すべて同じ値
> **`SHA3-256(あなたの ML-DSA-65 署名公開鍵)`** です。`--fingerprint` が表示する値、
> `--gen-keybundle` が印字する値、`--recipient-fingerprint` で pin する値、P2P で相手を pin
> する値 ── **全部同一**。これが identity そのもの。電話で 1 回照合すれば、以降はその値を
> 使い回します（別々の値を管理する必要はありません）。

---

## 0. 下準備 — 鍵ペアの生成

すべてのユースケースの前提。1 回だけ。

```bash
# 署名鍵ペア（ML-DSA-65）— 署名 / P2P 認証 / KeyBundle の identity に使う
nk-crypto-tool --mode pqc --gen-sign-key --key-dir keys
#   → keys/private_sign_pqc.key , keys/public_sign_pqc.key

# 暗号化鍵ペア（ML-KEM-768）— 暗号化の受信者鍵に使う
nk-crypto-tool --mode pqc --gen-enc-key --key-dir keys
#   → keys/private_enc_pqc.key , keys/public_enc_pqc.key
```

- ecc: `--mode ecc`（`*_sign_ecc.key` / `*_enc_ecc.key`）。
- hybrid: `--mode hybrid --gen-enc-key` で ML-KEM と P-256 の 2 対（`public_enc_hybrid_mlkem.key`
  / `public_enc_hybrid_ecdh.key` と各 private）。署名 identity は常に ML-DSA-65。
- TPM 封印: どの生成にも `--use-tpm` を足す。

**指紋の確認**（相手を pin するとき out-of-band で照合する 64 hex）:
```bash
nk-crypto-tool --mode pqc --fingerprint --signing-pubkey keys/public_sign_pqc.key
#   → Fingerprint: <64-hex>
```

---

## 1. 暗号化 — ファイルを相手に送る

受信者の**署名付き KeyBundle** に暗号化する（生の公開鍵の直接指定は廃止）。

### 受信者側（1 回だけ、鍵を配る）
```bash
nk-crypto-tool --mode pqc --gen-keybundle --key-dir keys \
    --signing-privkey keys/private_sign_pqc.key \
    --keybundle-handle alice \
    --keybundle-output alice.nkkb
#   → "…fingerprint: <64-hex>" を表示
```
これは新しい鍵を作らない。**§0 で作った暗号化公開鍵**（`public_enc_pqc.key`）を `--key-dir` から
規約名で拾い、あなたの ML-DSA identity（`--signing-privkey`）で**署名して束ねる**だけ（だから
gen-keybundle に暗号鍵を明示的に渡さなくてよい）。出力 `alice.nkkb` と、表示された**指紋を
out-of-band（電話等）で送信者へ**渡す。指紋は §0 の `--fingerprint` と同じ値。

- **hybrid の場合**: `--mode hybrid` で発行すると、束に **ML-KEM と P-256 の両方**が入る
  （送信者側の「hybrid→両方」と対応）。identity は常に ML-DSA-65。
- `--keybundle-expiry-secs <N>` で有効期限（現在から N 秒）を付与できる。

### 送信者側（暗号化）
```bash
nk-crypto-tool --mode pqc --encrypt \
    --recipient-keybundle alice.nkkb \
    --recipient-fingerprint <64-hex> \
    --output-file secret.enc \
    plain.txt
#   <64-hex> は受信者から out-of-band（電話等）で受け取った指紋（= 受信者 identity）
```
- 指紋 pin（`--recipient-fingerprint`）は**必須**。bundle 検証（指紋一致→self_sig→keybind）に
  通ってから暗号化する＝経路での鍵すり替え（MITM）を防ぐ。
- `--mode` が束から使う鍵を選ぶ: pqc→ML-KEM / ecc→P-256 / hybrid→両方。
- 期限切れの鍵は暗号化入口で拒否される。
- AEAD 切替: `--aead-algo AES-256-GCM`（既定）/ `ChaCha20-Poly1305`。

---

## 2. 復号 — 受け取ったファイルを開く

自分の**秘密鍵**で開く（KeyBundle は不要。使った AEAD はヘッダから自動認識）。

```bash
# pqc / ecc
nk-crypto-tool --mode pqc --decrypt \
    --user-privkey keys/private_enc_pqc.key \
    --output-file plain.out \
    secret.enc
```
hybrid は 2 つの秘密鍵を渡す:
```bash
nk-crypto-tool --mode hybrid --decrypt \
    --user-mlkem-privkey keys/private_enc_hybrid_mlkem.key \
    --user-ecdh-privkey  keys/private_enc_hybrid_ecdh.key \
    --output-file plain.out \
    secret.enc
```

---

## 3. 署名 — ファイルの作成者を証明する

自分の**署名秘密鍵**で切り離し署名（detached）を作る。

```bash
nk-crypto-tool --mode pqc --sign \
    --signing-privkey keys/private_sign_pqc.key \
    --signature doc.sig \
    doc.txt
#   → doc.sig（署名ファイル）
```
- ダイジェストは `--digest-algo`（既定 `SHA3-512`）で変更可。検証側は指定不要（署名から自動認識）。

---

## 4. 検証 — 署名が本物か確かめる

署名者の**公開鍵**で検証する。

```bash
# (推奨) まず署名者公開鍵の指紋を out-of-band 値と照合しておく
nk-crypto-tool --mode pqc --fingerprint --signing-pubkey signer_pub.key

nk-crypto-tool --mode pqc --verify \
    --signing-pubkey signer_pub.key \
    --signature doc.sig \
    doc.txt
#   → 成功時に verified、失敗時は非ゼロ終了
```
- 検証は raw `--signing-pubkey` を直接受け取る（署名鍵は自己認証的なので KeyBundle 化しない）。
  その鍵が本物かは**指紋の out-of-band 確認**で担保する。

---

## 5. P2P ssh（踏み台レス PQC シェル）

ポート開放なしで、相互 ML-DSA 認証の上に PTY シェルを張る（iroh トランスポート）。
サーバ・クライアント双方が相手を pin する default-deny。

### サーバ（シェルを提供する側）
```bash
nk-crypto-tool --serve-shell --mode pqc \
    --signing-privkey server/private_sign_pqc.key \
    --signing-pubkey  client/public_sign_pqc.key \
    [--shell-policy policy.txt] [--audit-log audit.log]
#   → 接続チケット nkct1… を表示（クライアントへ渡す）
```
- `--signing-pubkey` で**許可するクライアントを 1 つ pin**。複数許可は `--peer-allowlist <file>`
  （指紋を 1 行 1 つ列挙）。
- `--shell-policy` の各行（省略時は pin した相手にフル shell）:
  ```
  <クライアント指紋>  user=NAME  cmd-allow="ls,cat,uname"
  ```
  1 行目が指紋（空白区切り）、続く `user=` と `cmd-allow=` は**順不同**・どちらも任意。
  `user=` は昇格ではなくサーバ自身のユーザに限定。`cmd-allow` を付けると許可コマンドのみ
  （不在ならフル shell）。policy に無い指紋は拒否。
- `--audit-log` で接続・コマンドを記録。

### クライアント（シェルに入る側）
```bash
nk-crypto-tool --shell --connect <ticket> --mode pqc \
    --signing-privkey client/private_sign_pqc.key \
    --signing-pubkey  server/public_sign_pqc.key
#   → 対話 PTY。`Server authenticated successfully (auth: ML-DSA-65)` を確認
```
- `--signing-pubkey` で**サーバを pin**（なりすまし防止）。
- 一発コマンド実行は対話の代わりに `--shell-cmd "uname -a"`。

---

## 6. P2P scp（踏み台レス PQC ファイル転送）

シェルと同じ相互 ML-DSA 認証の上で、fingerprint 単位の read/write ポリシー＋パス confinement
付きファイル転送。ライブ進捗バー付き。

### サーバ（ファイルを置く側）
```bash
nk-crypto-tool --serve-scp --mode pqc \
    --signing-privkey server/private_sign_pqc.key \
    --signing-pubkey  client/public_sign_pqc.key \
    --scp-policy scp.policy
#   → 接続チケット nkct1… を表示
```
- `--scp-policy` の各行:
  ```
  <クライアント指紋>  read="/srv"  write="/srv"
  ```
  そのクライアントが読める/書けるディレクトリを限定（配下にパス confinement）。
- 複数クライアントは `--peer-allowlist <file>` 併用。

### クライアント（送受信する側）
```bash
# アップロード（put）: ローカル → リモート
nk-crypto-tool --scp-put local.tar /srv/local.tar --connect <ticket> --mode pqc \
    --signing-privkey client/private_sign_pqc.key \
    --signing-pubkey  server/public_sign_pqc.key

# ダウンロード（get）: リモート → ローカル
nk-crypto-tool --scp-get /srv/remote.tar local.tar --connect <ticket> --mode pqc \
    --signing-privkey client/private_sign_pqc.key \
    --signing-pubkey  server/public_sign_pqc.key
```
- 引数順: `--scp-put <ローカル> <リモート>` / `--scp-get <リモート> <ローカル>`。
- `--serve-scp` と `--serve-shell` は 1 プロセスでは排他（役割は 1 プロセス 1 つ）。

---

## 認証モデル早見（P2P shell / scp 共通）

| 誰が誰を | 手段 |
|---|---|
| サーバ→クライアント | `--signing-pubkey <client_pub>`（1 つ pin）または `--peer-allowlist <file>`（複数） |
| クライアント→サーバ | `--signing-pubkey <server_pub>`（サーバを pin、なりすまし防止） |
| 認可（何ができるか） | サーバ側 policy を**クライアント指紋**でキーイング（shell=cmd-allow / scp=read・write） |

pin する公開鍵の指紋は `--fingerprint --signing-pubkey <pub>` で確認できる（§0）。

---

## 動くデモ

`demos/` に各ユースケースのワンショット・デモ（vhs 収録）がある:
`p2p_shell_demo.sh`（ssh）/ `p2p_scp_demo.sh`（scp）/ `p2p_bundle_demo.sh`（KeyBundle 暗号化配送）。
README の該当 GIF も参照。
