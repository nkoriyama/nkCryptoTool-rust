# 純 Rust ストレージ移行設計 (SQLCipher → redb + アプリ層 AEAD)

- 作成日: 2026-06-18
- ステータス: 設計合意済み（案A 確定）。実装未着手。
- 関連: `SECURITY_PROFILE.md`（at-rest 脅威モデル）, `src/group/{storage,at_rest,processor}.rs`, `src/network/inbox.rs`
- 相談記録: AGY(Gemini 2.5 Pro) と方針レビュー実施済み（2026-06-18）

---

## 1. 目的と背景

`default` を純 Rust の `backend-rustcrypto` に切替済み（commit 6458b021）だが、`mls`
feature 構成は **SQLCipher（`rusqlite` の `bundled-sqlcipher`）が system `libcrypto` を
動的リンク**するため、Android/iOS のクロスコンパイルでリンク失敗する。

実測: `--features "backend-rustcrypto mls"` のバイナリは `openssl` クレート不在でも
`ldd` に `libcrypto.so.3` が出る。原因は SQLCipher のページ暗号のみ。

**ゴール**: `mls` 構成を完全 C-free にし、`cargo build --target aarch64-linux-android`
等が追加 C ツールチェーン無しで通るようにする。性能より移植性・依存ゼロを優先（方針は
[[project_rustcrypto_default_rationale]] と一貫）。

---

## 2. 決定: 案A (redb + アプリ層 AEAD)

| 案 | 内容 | 判定 |
|---|---|---|
| **A (採用)** | `redb`（純 Rust KV）+ レコード単位 XChaCha20-Poly1305。mls-rs の3トレイトを自前実装 | **C 依存ゼロ。方針に直球** |
| B | 素の bundled SQLite（libcrypto 不要）+ アプリ層 AEAD | SQLite の C(cc/NDK) が残る。実装工数は A とほぼ同じなので不採用 |
| C | `bundled-sqlcipher-vendored-openssl` | OpenSSL C を引き戻す。方針逆行で却下 |

実装工数の本体は「3トレイト自前実装 + blob 暗号化」で案 A/B 共通。同じ労力なら目的を
完全達成する **redb** を採る。

### 実装可能性の根拠
- `mls-rs-core` 0.27 は以下を**公開トレイト**として提供（provider-sqlite のフォーク不要）:
  - `GroupStateStorage`（`group/group_state.rs:66`）
  - `KeyPackageStorage`（`key_package.rs:59`）
  - `PreSharedKeyStorage`（`psk.rs:116`）
- これらを実装した型を `mls_rs::Client::builder()` に差せばよい（現状 `processor.rs:183-190`
  で `SqLite*Storage` を差している箇所を置換）。
- at-rest 鍵階層（DEK/KEK/at-rest.key）は既に純 Rust・DB エンジン非依存
  （`at_rest.rs`、`derive_aead_key`/`aes256gcm_encrypt`/`aes256gcm_decrypt` 等）。DEK(32B)を
  そのままレコード暗号鍵の素として流用できる。

---

## 3. 暗号設計（アプリ層 AEAD）

SQLCipher の「透過ページ暗号」を失う代わりに、**value を per-record AEAD** で暗号化する。

### 3.1 アルゴリズム: XChaCha20-Poly1305
- 既存 `chacha20poly1305` クレート（Cargo.toml:92, **非 optional 依存**）の `XChaCha20Poly1305`。
- 理由: per-record でランダム nonce を使うため、AES-GCM の 96-bit nonce では誕生日衝突
  リスク（nonce 再利用 = GCM 致命的鍵崩壊）。XChaCha20 は **192-bit nonce** で `OsRng`
  ランダム生成のまま衝突無視できる。
- 鍵: DEK(32B) を直接使わず、HKDF-SHA256 で用途別サブ鍵に**必ず分離**（domain separation）:
  - `k_value = HKDF(DEK, info=b"nkct-redb-value-v1")` → 32B。XChaCha20-Poly1305 の value 暗号鍵。
    **全レコード共通鍵 + レコード毎ランダム 24B nonce**（XChaCha の nonce 空間が広く衝突無視可）。
  - `k_bi    = HKDF(DEK, info=b"nkct-redb-blindindex-v1")` → 32B。HMAC-SHA256 Blind Index 鍵（§4.2）。
  - value 鍵と検索鍵が完全分離。DEK そのものは暗号にも HMAC にも使わない。

### 3.2 レコード暗号フォーマット
```
record = version(1) || nonce(24) || ciphertext || tag(16)
```
- AEAD の **AAD** に以下を束縛し、レコード入替（swap）/別テーブル混入を AEAD タグで検出:
  ```
  aad = db_binding || table_id(1) || logical_key
  ```
  - `db_binding`: DB ファイル名由来（既存 `at_rest::db_binding` 思想を踏襲）。同一鍵を
    複数 DB で共有しても取り違えを検出。
  - `table_id`: group_state / epoch / key_package / psk / envelope / prekey / checkpoint を
    区別する 1 バイト定数。
  - `logical_key`: そのレコードの論理キー（group_id、epoch_id、psk_id 等）。配置改竄を検出。

### 3.3 nonce 管理
- 各 write で `OsRng` から 24B 新規生成（再利用禁止）。`Zeroizing` で平文/鍵を保持。
- redb への書込は CoW で旧版が一時残存しうる点に留意（§6 参照）。

---

## 4. redb スキーマ設計

redb は named table に `(key: &[u8], value: &[u8])`。論理キーは平文だが、value は §3 で暗号化。

### 4.1 groups.db 相当（`group_state` 系）
| テーブル | key | value(暗号化前) | 備考 |
|---|---|---|---|
| `mls_group_state` | `group_id` | GroupState.data | 1 group 1 レコード |
| `mls_epoch` | `group_id ‖ epoch_id(be u64)` | EpochRecord.data | prior epoch キャッシュ。range scan で group 内列挙 |
| `mls_key_package` | `kp_id` | KeyPackageData(codec) | join 成功で delete |
| `mls_psk` | `psk_id` | PreSharedKey | |
| `mls_app` | `"mls:identity:sk"` 等 | 任意 | 署名鍵などの KV |

- `group_id` は**ランダム値**なので平文キーでも機微低（許容）。
- `GroupStateStorage::write` は **1 redb 書込トランザクションで state + epoch_inserts +
  epoch_updates をアトミックに**適用（トレイト doc の atomic 要件、`group_state.rs:92-97`）。
- `max_epoch_id`/`epoch` は `mls_epoch` の `group_id` プレフィックス range scan で実装。

### 4.2 inbox.db 相当（relational 的アクセスへの対応）
inbox は SQL で `WHERE recipient=? AND id>? ORDER BY id ASC LIMIT ?`、`COUNT`、FIFO 削除を
使う（`inbox.rs:812-814,931-933,1027`）。redb では**複合キー + range scan**でモデル化:

| テーブル | key | value | 用途 |
|---|---|---|---|
| `inbox_env` | `BI(recipient) ‖ id(be u64)` | payload(MLS暗号文を **value AEAD で二重暗号**) + sender/created_at メタも value 内に同梱暗号 | poll: `BI(recipient)` プレフィックス + `id>cursor` range |
| `inbox_prekey` | `BI(recipient) ‖ id(be u64)` | signed prekey | FIFO 取得・件数・古いもの削除を range で |
| `inbox_checkpoint` | `BI(peer)` | epoch(u64) | 単純 KV |
| `inbox_meta` | `"next_id"` | u64 | 単調増加 id 採番（SQLite の AUTOINCREMENT 代替） |

- **`BI(x)` = Blind Index = HMAC-SHA256(k_bi, x)**（`k_bi` は DEK 由来サブ鍵, `hmac` クレート）。
  recipient/sender を**平文キーにせず**検索可能にする。残留リークは「等価性・件数・タイミング」
  のみ（検索可能暗号の原理的限界、脅威モデルに明記）。
- **決定（#3）**: `created_at`/`sender`/`payload` は全て value 内に暗号化同梱（payload も
  二重暗号）。redb の全 value を一律 AEAD 経路に通すことでコード分岐を無くし、AAD バインドの
  恩恵（リレー側のレコード入替・改竄検出）を payload にも効かせる。SQLCipher が透過で隠して
  いた「誰がいつ誰宛て」の平文露出をここで補う。平文で残るのは検索に要る `BI(recipient)` と
  単調 `id` のみ。

---

## 5. 移行（既存 SQLCipher DB → redb）

### 5.1 最重要: 移行コードを隔離 feature 化（決定 #4）
旧 DB を読むには結局 SQLCipher+libcrypto が要る。これをメイン/モバイルビルドに残すと
目的未達。**`legacy-sqlcipher-migration`（仮）feature** に隔離し、通常ビルド・モバイル
ビルドからは完全にコンパイル除外する。
- **通常/モバイル配布バイナリ**: redb のみ（C-free）。移行コードは一切含まない。
- **トリガは明示サブコマンドのみ**（例 `--mls-cmd migrate-from-sqlcipher`）。移行ビルド内
  であっても起動時自動検出はしない（自動検出すると「自動移行」UX への将来流入や、誤って
  通常起動経路に SQLCipher 依存が混ざる温床になるため、明示実行に限定して経路を一本化）。
- **旧 DB を通常ビルドが検出した場合**: 黙って失敗せず、「`legacy-sqlcipher-migration`
  ビルドで `migrate-from-sqlcipher` を一度実行せよ」という明確なエラーで案内する。
- 配布運用: 旧ユーザ向けに移行 feature 有効の一回限りバイナリ（or 別名 `*-migrate`）を提供。

### 5.2 アトミック手順
1. 既存 DEK を `at_rest::resolve_dek` で復元し SQLCipher DB を開く。
2. 同 DEK 由来サブ鍵で `groups.redb`（新規・別名）を作成。
3. 旧 DB から全件 read → §3 形式で暗号化（+ inbox は `BI` 化）→ 新 DB へ write。
   - inbox 履歴が巨大化しうるため**バッチ/ストリーミング**で（全件メモリ展開しない）。
4. 新 DB を flush して安全にクローズ → 鍵で開けることを検証。
5. **検証成功時のみ**旧 SQLCipher DB を `.bak` リネーム（or unlink）し新 DB を本番名へ。
   WAL/journal サイドカーも処理。中断時は旧 DB を破壊しない（既存マイグレーション思想踏襲、
   `at_rest::migrate_plaintext_to_sqlcipher` を参考）。

---

## 6. 留意点 / 既知リスク

1. **redb の CoW ファイル肥大化**: 古い版領域が残りやすい。groups.db は小さく実害軽微だが、
   inbox 履歴が大きい場合はコンパクションと実測評価が必要。
2. **平文残存（CoW/旧版）**: redb の旧版ページに古い暗号文が残るが、value は常に暗号化済み
   なので平文露出は無い。鍵更新（DEK ローテーション）時は全レコード再暗号 + 新ファイルへ
   退避が確実。
3. **クラッシュ安全性**: redb は ACID/MVCC。`write` を単一トランザクションにまとめれば
   group state 部分書込み破損を回避（トレイト要件と一致）。
4. **検索キーの平文/等価リーク**: group_id は許容。inbox は `BI` で緩和するが等価・件数・
   タイミングは残る。inbox サーバは準信頼前提（既存脅威モデル）なので許容範囲だが
   `SECURITY_PROFILE.md` に劣化点を明記する。
5. **ファイル権限**: 既存同様 `0o600`（cfg(unix)）を新 DB にも適用。Windows は別途
   （[[project_windows_hardening_debt]]）。

---

## 7. 実装フェーズ案

- **P1**: redb 依存追加 + `GroupStateStorage`/`KeyPackageStorage`/`PreSharedKeyStorage` の
  redb 実装（groups.redb）。レコード AEAD ヘルパ（XChaCha20-Poly1305 + HKDF サブ鍵 + AAD）。
  ラウンドトリップ + mls-rs Client 結線テスト。
- **P2**: inbox を redb + Blind Index へ移植（複合キー range scan、id 採番、FIFO/COUNT）。
- **P3**: 移行ツールを `legacy-sqlcipher-migration` feature で実装（§5）。
- **P4**: `mls` の依存から `rusqlite`/`mls-rs-provider-sqlite` を撤去。
  `cargo build --target aarch64-linux-android` で C-free を確認（libcrypto 不在を `ldd`/
  リンク検証）。`SECURITY_PROFILE.md` 更新。

完了条件: `--features "backend-rustcrypto mls"` のリンク済みアーティファクトに libcrypto
依存が無く、全 round-trip テストが緑。

---

## 8. 決定済み事項（2026-06-18 確定）

- **#1 redb バージョン**: 最新 **4.1.0**。`redb = "4"` でピン。ACID/MVCC・range scan・savepoint
  あり。複合キー range は `&[u8]` 辞書順で実現。注意: redb はメジャー跨ぎで on-disk フォーマット
  が変わり得る → 新規 DB なので現状無問題、将来の redb メジャー upgrade 時のみ自前データ移行が要る。
- **#2 HKDF サブ鍵**: DEK を直接使わず `k_value`(value 暗号) / `k_bi`(Blind Index) に HKDF で
  分離（§3.1 に確定仕様）。
- **#3 inbox payload**: **二重暗号する**。全 value を一律 AEAD 経路に通し payload/メタを
  まとめて暗号化（§4.2）。
- **#4 移行トリガ**: **`legacy-sqlcipher-migration` feature + 明示サブコマンドのみ**。自動検出
  はしない。通常/モバイルビルドは移行コードを含まず C-free（§5.1）。
