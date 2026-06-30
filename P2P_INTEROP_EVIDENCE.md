# 実証エビデンス（相互運用・相互接続）

`P2P_SHELL_COMPARISON.md` の設計説明に対する**実証面の裏付け**をまとめる。
記載は2層に分ける:

- **Part 1 — 記録済み（再現可能 / 既存実績）**: 自動テスト（CI 実行）と、実機で
  確認済みの相互接続。新規計測なしで事実として記録できるもの。
- **Part 2 — 未計測（今後）**: NAT 越え成功率・遅延実測など、計測を要する項目。
  ここは数値を**まだ埋めていない**ことを明示し、計測方法だけ先に定義する。

> 原則: 本ドキュメントは未計測の数値を推定で埋めない。Part 1 は再現コマンドまたは
> コミット/テスト名で追跡でき、Part 2 は計測されるまで「未計測」と記す。

---

## Part 1 — 記録済み（再現可能）

### 1.1 クロスバックエンド暗号相互運用（自動・CI）

OpenSSL バックエンドと RustCrypto バックエンドを**別バイナリとしてビルドし、
一方で暗号化/署名 → 他方で復号/検証**する双方向テスト（`tests/interop.rs`）。
OpenSSL 側は ML-KEM を確実に使うため vendored OpenSSL 3.6.x を強制ビルドし、
ホスト/CI の libssl バージョンに依存しないようにしている。

| テスト | 内容 |
|---|---|
| `test_ecc_interop_encryption_bidirectional` | ECC ハイブリッド暗号を openssl⇄rustcrypto 双方向で復号 |
| `test_ecc_interop_signature_bidirectional` | ECDSA 署名を openssl⇄rustcrypto 双方向で検証 |
| `test_pqc_interop_encryption_bidirectional` | PQC（ML-KEM）暗号を openssl⇄rustcrypto 双方向で復号 |

意義: 2 実装が**同一ワイヤ形式**を共有する＝アルゴリズム実装に依存しない相互運用性。

再現:

```bash
cargo test --test interop
```

### 1.2 E2E 暗号サイクル（自動・サブプロセス CLI）

実バイナリを起動し、暗号化 → 復号の往復を検証（`tests/e2e.rs`）。

- `test_ecc_e2e_cycle` / `test_ecc_signing_e2e`
- `test_pqc_e2e_cycle`（ML-KEM）
- `test_hybrid_e2e_cycle`（ECDH ＋ ML-KEM ハイブリッド）

### 1.3 E2E ファイル転送＋敵対的検証（自動）

ストリーミング転送の正常系とフレーム改竄系（`tests/e2e_file_transfer.rs`）。

| 種別 | テスト |
|---|---|
| 正常系 | `test_e2e_file_transfer_small_subchunk` / `_medium_around_1mib` / `_large_10mib` |
| 改竄検知 | `test_e2e_aead_tampering`（AEAD タグ改竄を拒否） |
| 長さ偽装 | `test_e2e_chunk_len_forgery` |
| 認証前永続化なし | `test_recv_finalize_discards_unverified_on_failure` / `_commits_on_success` |

意義: 1MiB・10MiB の実サイズで往復が成立し、かつ**改竄は復号失敗として弾かれ、
検証前データはディスクに確定しない**（TOCTOU/認証前永続化の回避）ことを機械検証。

### 1.4 ハンドシェイク改竄検知（自動）

`tests/e2e_handshake_tampering.rs::test_handshake_signature_tampering` ——
ハンドシェイク署名を改竄すると接続が確立しないことを検証。
セキュリティ・マンデート（`scripts/mandate_check.sh`）が敵対的 E2E の本数
（file_transfer:2, handshake:1）を release-blocking で監視している。

### 1.5 ハンドシェイク transcript のワイヤ互換（クロスバージョン実機）

handshake transcript 構築を共有 `TranscriptBuilder` に集約するリファクタ
（commit `7556336` 系列）の際、**新ビルダー版クライアント ↔ 旧インライン版サーバ
（別マシン nkwire 上、未改修バイナリ）**で実ハンドシェイクが成立し、サーバ認証成功・
リモートコマンド実行まで到達した。

意義: transcript が 1 バイトでも変われば salt（HKDF）→ 鍵が食い違い認証が落ちる。
旧バイナリと繋がった事実が、リファクタの**バイト完全互換**を実証している。
バイトレイアウト自体は KAT（`p2p::processor::tests::handshake_transcript_kat`）で
ピン留め済み（golden 一致＋ kem_ct 除去で赤になる検出力を確認）。

### 1.6 全テストスイート

最新の確認時点で **106 passed / 1 ignored**（`cargo test`）。

```bash
cargo build            # まずコンパイルが通ること
cargo test             # 全スイート
cargo test --test interop   # クロスバックエンド相互運用のみ
```

### 1.7 実機・踏み台レス P2P シェル（手動確認）

NAT 配下ホストへ踏み台・ポート開放なしで対話シェル接続を、複数アーキテクチャ間で
手動確認済み（`P2P_SHELL_DESIGN.md` §12 の実機計画に対応）。

| 項目 | 結果 |
|---|---|
| 接続元 → 接続先 | bazzite → rustdev（x86_64）／ bazzite → nkwire（arm64/aarch64） |
| 対話シェル | ✓（PTY ブリッジ・raw 透過） |
| 端末リサイズ（WINSZ） | ✓ |
| 終了コード伝播 | ✓ |
| 未許可指紋の拒否 | ✓ |
| 監査ログ | ✓ |

MLS/転送系も別途、アドレス帳・グループファイル転送・3 端末実機で確認済み。

> 注: 1.7 は**手動・記録ベース**で、自動テストではない。再現には実機 2 台以上と
> 事前のチケット交換が必要。成功率・遅延の定量値は Part 2 で計測する。

---

## Part 2 — 未計測（計測方法を先に定義）

以下は**まだ計測していない**。各項目に計測の前提と手順だけ定義しておき、
測定後に数値表へ置き換える。

### 2.1 NAT 越え成功率（直結ホールパンチ成立率）

- 目的: NAT 種別ごとに、relay を介さず**直接ホールパンチ**が成立する割合。
- 計測軸（案）: full-cone / restricted-cone / port-restricted / symmetric / CGNAT、
  および IPv4/IPv6・同一 NAT 配下か否か。
- 手順（案）: 既知 NAT 種別の環境ペアで N 回接続し、確立した経路が direct か relay か
  を記録（ステータスバー v2 のメトリクスが direct/relay と RTT を報告する）。
- 記録欄: **未計測**

### 2.2 経路別レイテンシ（RTT 実測）

- 目的: direct 経路と relay 経由の RTT 分布。
- 計測元: iroh `Connection::paths()` の選択パス RTT（`--tui` v2 が表示する値）。
- 記録欄: **未計測**（direct 中央値 / relay 中央値 / p95）

### 2.3 relay フォールバック率

- 目的: 全接続のうち relay 経由に落ちた割合（直結成立しなかった割合）。
- 記録欄: **未計測**

### 2.4 スループット

- 目的: ファイル転送・シェル貼り付けの実効スループット（direct / relay 別）。
- 既存の自動テストは 10MiB までの正当性は担保するが、速度は計測していない。
- 記録欄: **未計測**

---

## 関連ドキュメント

- `P2P_SHELL_COMPARISON.md` — 設計・到達手段の比較表（本ドキュメントが実証面を補う）
- `P2P_SHELL_DESIGN.md` — P2P シェルの設計メモ（§12 テスト計画）
- `P2P_SSH_USAGE_GUIDE.md` — 利用ガイド
