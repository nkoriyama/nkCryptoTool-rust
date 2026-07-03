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

### 計測ツール: `--conn-metrics` プローブ

シェルクライアントに `--conn-metrics` を付けると、接続・ハンドシェイク完了後に
経路が落ち着くのを待ち（ホールパンチの relay→direct 昇格を見込んで数秒）、
選択された経路種別と RTT を 1 行で出力してシェルを開かず終了する:

```bash
nk-crypto-tool --conn-metrics --connect 'nkct1...' --mode pqc \
  --signing-privkey ~/nkkeys/private_sign_pqc.key \
  --signing-pubkey  ./server_public_sign_pqc.key
# => stderr: nkct-metrics relay=false rtt_ms=23
```

`relay=true/false` が直結かリレー経由か、`rtt_ms` が選択パスの RTT。これを N 回
回せば 2.1〜2.3 が定量化できる。サーバ（`--serve-shell`）は通常どおり起動しておく。

N サンプル収集の例（相手チケットを `$T` に入れて）:

```bash
for i in $(seq 1 50); do
  nk-crypto-tool --conn-metrics --connect "$T" --mode pqc \
    --signing-privkey ~/nkkeys/private_sign_pqc.key \
    --signing-pubkey ./server_public_sign_pqc.key 2>&1 \
    | grep -oE 'nkct-metrics .*'
done | tee samples.txt
# relay 率: grep -c 'relay=true' samples.txt
# RTT 分布: grep -oE 'rtt_ms=[0-9]+' samples.txt | cut -d= -f2 | sort -n
```

> 注: 直結ホールパンチの成立可否は両端の NAT 種別に依存するため、代表値を出すには
> 複数の実 NAT 環境での計測が要る。以下は実測済みパスの記録。

### 計測結果 — 第1パス: bazzite ↔ nkwire（2026-07-01）

- 環境: **bazzite（x86_64）→ nkwire（aarch64）**、同一 Tailscale テイルネット/LAN 近接。
  クロスアーキかつクロスバージョン（新 `TranscriptBuilder` クライアント ↔ 旧 inline
  サーバ `15c4773`）で全接続がハンドシェイク成立。
- 手法: `--conn-metrics` プローブを 20 回（プローブごとに新規エンドポイント）。
- **経路種別 / RTT（成功した接続 n=13）**:
  - **relay フォールバック率 0%**（13/13 が `relay=false` ＝ 直結ホールパンチ成立）
  - **RTT**: 中央値 **5 ms**、平均 5.5、範囲 **2–9 ms**、p95 9 ms
- **接続確立率**: 20 試行中 13 成功（**約 65%**）。失敗 7 は**すべてクライアント側の
  iroh connect 確立タイムアウト**（handshake/認証以前。接続できたクライアントは
  サーバ側で全員認証成功）。
  - **注意**: この失敗率は**プローブがプロセス毎に新規エンドポイントを立てる
    コールドスタート＋連射**の影響を含む（relay ホームのウォームアップが毎回発生）。
    永続クライアントはコールドスタートを 1 回のみ負担するため、この 65% を
    NAT 越え成功率そのものと解釈してはならない。純粋な NAT 越え成功率の分離は
    2.1（永続エンドポイントでの再接続計測）で行う。

### 計測結果 — 第2パス: bazzite（VPN 配下）↔ OCI VPS（2026-07-02）

「片方が VPN 上にいても繋がるか」の実測。クライアント（bazzite, 自宅 NAT 配下）を
Tailscale exit node（WireGuard ベースの full-tunnel VPN）配下に置き、全トラフィックを
別ホスト経由にした状態で、tailnet 外の OCI VPS（公開 IP・クラウド FW、Oracle Linux 9.7
x86_64）の `--serve-shell` へ接続した。両端 `--discovery n0`、`--mode pqc`（ML-DSA-65 相互
認証）、サーバは musl 静的ビルド（`5469c8f`）。

| 条件 | 試行 | 成功 | relay フォールバック | RTT 中央値（範囲） |
|---|---|---|---|---|
| ベースライン（VPN なし） | 10 | **10/10** | 0%（10/10 direct） | **4 ms**（4–5） |
| **VPN（exit node）経由** | 20 | **20/20** | **0%**（20/20 direct） | **5 ms**（4–6） |

- VPN トンネル越しでも**全接続で直結ホールパンチが成立**し、relay に落ちなかった。
  RTT のペナルティは中央値 +1 ms（exit node 1 ホップ分）。
- メトリクスだけでなく実シェルも確認: VPN 経由の `--shell-cmd` が成功し、サーバ側
  監査ログに `allow`（指紋・降格ユーザ付き）と `session end exit=0` が記録された。
- 第1パスで見えたコールドスタート失敗（65% 成功）は本パスでは発生せず **30/30 成功**。
  対向が公開 IP の VPS（NAT なし）だと安定する、という示唆は立つが、**第1パスとは
  変数が複数同時に違う**（対向の NAT 有無に加え、バイナリが `5469c8f` 再ビルド後、
  discovery 設定も異なる）ため単独要因への帰属はまだできない。切り分けは 2.1 の
  再計測で行う。
- **限界**: 使用した VPN 出口はクライアントと同一 WAN 上にある。出口が地理的に遠い
  商用 VPN や、出口側が CGNAT/symmetric NAT の場合の direct 成立率・relay 率は未計測
  （その場合も relay 経由での接続成立は設計上期待できる）。

### 2.1 NAT 越え成功率（直結ホールパンチ成立率）

- 目的: NAT 種別ごとに、relay を介さず**直接ホールパンチ**が成立する割合。
- 計測軸（案）: full-cone / restricted-cone / port-restricted / symmetric / CGNAT、
  および IPv4/IPv6・同一 NAT 配下か否か。
- 手順（案）: 既知 NAT 種別の環境ペアで N 回接続し、確立した経路が direct か relay か
  を記録（ステータスバー v2 のメトリクスが direct/relay と RTT を報告する）。
- 記録欄: **一部計測**（bazzite↔nkwire は同一テイルネットで直結成立。
  bazzite（VPN 配下）↔ OCI VPS は 30/30 直結 — 第2パス参照。異なる NAT 種別の分離
  （cone/symmetric/CGNAT）と遠隔 VPN 出口は**未計測**）。
- **TODO — 第1パスの再計測（現行バイナリ）**: bazzite↔nkwire を `5469c8f` 以降の
  バイナリで 20 連射し、第1パスのコールドスタート失敗（成功率 65%）が再現するかを
  対照実験として確認する。再現しなければ、あの失敗は NAT 要因ではなく旧ビルド／
  discovery 設定要因だった可能性が立つ（第2パスの 30/30 と切り分けるにはこれが要る）。

### 2.2 経路別レイテンシ（RTT 実測）

- 目的: direct 経路と relay 経由の RTT 分布。
- 計測元: iroh `Connection::paths()` の選択パス RTT（`--conn-metrics` / `--tui` v2）。
- 記録: **direct** = 中央値 5 ms / 平均 5.5 / 範囲 2–9 / p95 9（bazzite↔nkwire, n=13）。
  **relay 経由の RTT は未計測**（この経路では直結が常に成立しリレーに落ちなかったため）。

### 2.3 relay フォールバック率

- 目的: 全接続のうち relay 経由に落ちた割合（直結成立しなかった割合）。
- 記録: bazzite↔nkwire（同一テイルネット）で **0%**（13/13 直結）。
  bazzite（VPN 配下）↔ OCI VPS でも **0%**（20/20 直結、第2パス）。CGNAT/symmetric
  NAT 越えのフォールバック率は**未計測**。

### 2.4 スループット

- 目的: ファイル転送・シェル貼り付けの実効スループット（direct / relay 別）。
- 既存の自動テストは 10MiB までの正当性は担保するが、WAN 実効速度は未計測。

#### 2.4.1 scp オーバーヘッドの切り分け（loopback + tmpfs, CPU 律速, 2026-07-02）

「純プロトコル／暗号コスト」を露出させるため **loopback + tmpfs**（ネットワークと
ディスクを排除）で 512 MiB を転送。同一マシンなので送受で CPU を分け合う分、実 2 台
より両者とも低めに出る（**相対比較としては有効**）。

| 対象 | スループット |
|---|---|
| baseline（`cat`, 暗号もプロトコルも無し＝メモリ帯域上限） | ~3660 MB/s |
| OpenSSH `scp`（localhost sshd, カーネル TCP, 単一暗号） | **~1700 MB/s** |
| 本実装 P2P scp（iroh QUIC, 二重 AEAD） | **~620 MB/s** |

620 MB/s の内訳を容疑者ごとに潰した:

| 容疑者 | 判定 | 根拠 |
|---|---|---|
| チャンクサイズ | ❌ 律速でない | 64→120 KiB で +3%、1 MiB は**逆に悪化**（464 MB/s）。最適は 64–120 KiB |
| 二重暗号（PQC の代償） | ❌ 主因でない | AES-256-GCM は AES-NI で単パス **~23 GB/s**（`openssl speed`, 16 KB ブロック）。二重でも ~11 GB/s＝観測の **18 倍**上 |
| アプリ層コピー（`to_vec`+`encode`） | △ **+7%** | 排除で 619→**664 MB/s**（commit: bulk Data を平文バッファへ直接読み込み in-place 封止） |
| **ユーザ空間 QUIC（iroh）+ async ランタイム** | ✅ **本丸** | 上記を全て潰しても残る 5 倍超の開き。OpenSSH との差の大半は**カーネル TCP vs ユーザ空間 QUIC** |

- **接続あたり固定コスト**（1 バイト転送）: OpenSSH ~73 ms / 本実装 **~17 ms**。
  PQC ハンドシェイク（ML-KEM-768 + ML-DSA-65 相互）込みで**接続確立は OpenSSH より
  ~4 倍軽い**（sshd の fork+exec+auth vs 単一プロセスの QUIC 接続）。「PQC は重い」への反証。
- **判断**: 二重暗号は誤差、易しい果実（コピー +7%）は回収済み、本丸の QUIC チューニング
  （ストリームバッファ拡大・GSO/GRO・並列ストリーム）は効果不透明かつ **WAN では網律速で
  差が消える**（620 も 1700 も数十〜数百 Mbps の WAN 帯域よりはるか上）ため**保留**。
  この 2.7 倍差が効くのは 1 Gbps 超の LAN か CPU 制約下のみ。
- 限界: これは CPU 律速の相対比較。**WAN 実測（VPS への 512 MiB 実転送）は未取得**
  （E2.1.Micro の 0.48 Gbps が上限になる想定）で、「WAN で ssh と同等」は現時点で推定。

#### 2.4.2 put パイプライン化の効果（VPS 実 RTT, 多ファイル）

多ファイル転送は per-file の ack 往復が律速になるため、`put` を「送信 + ack 回収の並行化」に
した。VPS 実 RTT 経由の A/B（直列＝親コミット `799dc652`、ワイヤ互換・差はクライアントのみ）で、
**400 小ファイル `put -r` が直列 ~3.6s → パイプライン ~2.0s（44% 短縮、転送部分は ~9 倍）**。
効果は「ファイル数 × RTT」に比例。詳細は [`P2P_SCP_PIPELINE_REPORT.md`](./P2P_SCP_PIPELINE_REPORT.md)。

---

## 関連ドキュメント

- `P2P_SHELL_COMPARISON.md` — 設計・到達手段の比較表（本ドキュメントが実証面を補う）
- `P2P_SHELL_DESIGN.md` — P2P シェルの設計メモ（§12 テスト計画）
- `P2P_SSH_USAGE_GUIDE.md` — 利用ガイド
- `ZTNA_AVAILABILITY.md` — ZTNA / egress 制御下の可用性（実測 + 運用指針）
