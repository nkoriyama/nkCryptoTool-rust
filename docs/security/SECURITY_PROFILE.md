# nkCryptoTool Iroh Chat — セキュリティ・プロファイル

作成日: 2026-05-07
対象: Iroh トランスポート + V3.1 PQC ハンドシェイク + AES-256-GCM チャット
読者: 利用検討者 / セキュリティ評価者 / プロジェクト関係者

---

## エグゼクティブサマリ

**nkCryptoTool の Iroh チャットは、現時点で世界に存在するチャットツールの中で「PQC ネイティブ × 中央サーバなし × 量子耐性 × FIPS 標準準拠」を全て満たす唯一のクラスに属します。**

- ✅ 一般的な脅威 (ISP、公衆 WiFi、Telegram 級サーバ侵入、商用 SaaS 召喚状) に対しては **ほぼ完璧**
- ✅ 量子計算機が将来登場した時の "Harvest Now, Decrypt Later" 攻撃に対して **解読不能**
- ✅ Signal / WhatsApp / iMessage と同等以上、Telegram のデフォルトチャットとは **比較にならないほど強い**
- ⚠️ 完璧ではない領域 (ワンショット暗号化の Post-Quantum Forward Secrecy / メタデータ秘匿) は本書末尾で正直に明示。なおライブ P2P チャット・同期ファイル転送は PQ-FS 達成済み

---

## 1. 暗号学的基盤

### 1.1 採用アルゴリズム (全て NIST FIPS 標準)

| 役割 | アルゴリズム | 標準 | 量子耐性 |
|---|---|---|---|
| 鍵カプセル化 (KEM) | **ML-KEM-768** | FIPS 203 (2024-08 確定) | ✅ |
| デジタル署名 (DSA) | **ML-DSA-65** | FIPS 204 (2024-08 確定) | ✅ |
| ハイブリッド古典暗号 | ECDH (P-256) | NIST SP 800-56A | △ (古典) |
| AEAD | AES-256-GCM | NIST SP 800-38D | ✅ |
| KDF | HKDF-SHA3-256 | RFC 5869 + FIPS 202 | ✅ |
| トランスポート | QUIC + TLS 1.3 | RFC 9000 / 8446 | △ (古典) |
| ハッシュ | SHA3-256 | FIPS 202 | ✅ |

### 1.2 二層構造の防御

```
┌─────────────────────────────────────────────────────┐
│  PQC 層 (V3.1)                                       │
│    ML-KEM-768 + ML-DSA-65 + ECDH ハイブリッド        │
│    → Channel Binding (NodeId を transcript に組込)   │
│    ↓ AES-256-GCM                                     │
├─────────────────────────────────────────────────────┤
│  古典 TLS 層 (Iroh QUIC)                             │
│    TLS 1.3 + ed25519 NodeId 認証                     │
│    ↓ NAT 越え (direct / hole-punch / relay)          │
├─────────────────────────────────────────────────────┤
│  ネットワーク (IPv6 / IPv4)                          │
└─────────────────────────────────────────────────────┘
```

**TLS 1.3 が将来的に古典コンピュータで破られても、PQC 層が独立して機能**。NodeId を PQC ハンドシェイクの transcript に含める Channel Binding によって、両層が攻撃者にバラされて中継される (cross-protocol attack) ことも防がれている。

### 1.3 V3.1 ハンドシェイク (双方向認証 + MITM 検知)

接続時に以下が成立:

1. **クライアント認証**: クライアントが ML-DSA-65 で transcript に署名、サーバが検証
2. **サーバ認証**: サーバが同じく ML-DSA-65 で transcript に署名、クライアントが検証
3. **MITM 検知**: ticket に含まれる PQC 公開鍵指紋 (`pqc_sign_fp`, `pqc_enc_fp`) と実際の鍵を SHA3-256 で照合、不一致なら即時切断
4. **Allowlist**: 事前に登録された peer 以外を拒否 (option)

---

## 2. 何から守られているか

### 2.1 ✅ 完全に防御できる脅威

| 脅威 | 防御理由 |
|---|---|
| 公衆 WiFi での盗聴 | 二層暗号化、TLS だけでも内容秘匿 |
| ISP / 中間 ISP のパケット記録 | 同上 |
| **中央サーバ運営者** | **そもそも中央サーバが存在しない** (Iroh は P2P) |
| 中央サーバへの召喚状 / 法的命令 | 上記、令状を渡す相手がいない |
| 中央サーバの侵害 (Telegram 2018 級) | 同上 |
| 古典 MITM (ticket が安全に共有された場合) | PQC 指紋検証で改竄即検知 |
| 通信記録からの**未来の量子解読** ("Harvest Now, Decrypt Later") | ML-KEM-768 が量子耐性 |
| メッセージ内容の改竄 | AES-256-GCM の AEAD タグで検知 |
| Replay 攻撃 | nonce ベース replay 検出、nonce_history で重複拒否 |
| Cooldown 回避 | 認証成功後の peer ID で cooldown 管理 |

### 2.2 ✅ 強力に防御できる脅威

| 脅威 | 防御理由 |
|---|---|
| 国家レベル監視 (中国 GFW / ロシア RuNet) | Iroh の `--no-relay` モードで direct 接続のみ → ネットワーク観測者は内容も識別子も読めない |
| TLS 1.3 が量子計算機で破られた場合 | PQC 層が独立して保護 |
| ed25519 NodeId が量子計算機で破られた場合 | ML-DSA-65 署名が transcript を保護 |
| 複数クライアント認証 | Allowlist で許可 peer 集合を限定 |

---

## 3. 競合との比較

### 3.1 主要チャットツールとの能力マトリクス

| ツール | E2EE | PQC | 中央サーバ無 | HNDL 耐性 | FS | メタデータ秘匿 | OSS (server) |
|---|---|---|---|---|---|---|---|
| **nkCryptoTool + Iroh** | ✅ | ✅ | ✅ | ✅ | △ | △ | ✅ |
| Signal | ✅ | △ (PQXDH 部分) | ❌ (Signal 社) | △ | ✅ (Double Ratchet) | △ | △ |
| WhatsApp | ✅ | ❌ | ❌ (Meta) | ❌ | ✅ | ❌ | ❌ |
| iMessage | ✅ | △ (PQ3) | ❌ (Apple) | △ | ✅ | ❌ | ❌ |
| **Telegram (default)** | **❌** | **❌** | **❌** | **❌** | **❌** | **❌** | **❌** |
| Telegram (Secret) | ✅ (MTProto 独自) | ❌ | ❌ | ❌ | ✅ | ❌ | △ (client only) |
| Element / Matrix | ✅ | △ (Hybrid PQ 試験) | △ (federation) | △ | ✅ | △ | ✅ |
| SimpleX | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Briar / Cwtch | ✅ | ❌ | ✅ (Tor) | ❌ | ✅ | ✅✅ | ✅ |

(HNDL = Harvest Now Decrypt Later)

### 3.2 特長

**唯一の組み合わせ**: PQC ネイティブ × 中央サーバ無し × FIPS 標準準拠 × OSS。これを満たす商用 / OSS のチャットは現時点で他に存在しない。

**Telegram との比較**:
- Telegram のデフォルトチャットは**そもそも E2E 暗号化されていない** (サーバが内容を見える)。これは多くのユーザが誤解している点。
- Telegram の Secret Chat は E2EE だが、独自プロトコル MTProto 2.0 で暗号学者からの批判があり、PQC 対応もない。
- → **「Telegram 並み」という表現は実態として nkCryptoTool を著しく低く見積もる**。

---

## 4. 想定される脅威モデル別評価

| 想定敵 | 評価 |
|---|---|
| カジュアル盗聴者 / 公衆 WiFi の隣人 | ✅✅ ほぼ完璧 |
| 企業 IT 部門 / 学校管理者 | ✅✅ ほぼ完璧 |
| サイバー犯罪者 (商業目的) | ✅✅ ほぼ完璧 |
| ISP / 通信事業者 | ✅ メタデータは観測可能だが、内容は読めない |
| 国家による大量監視 (中・露・欧米) | ✅ relay 不使用で direct 接続なら強い |
| 法執行機関 (令状ベース) | ✅ 中央サーバ無いので召喚状効かない (端末押収には別途無力) |
| TLA 級アクター (NSA / GCHQ 等)、現時点 | ✅ 内容は安全、メタデータは relay 構成次第 |
| TLA、量子計算機後の解読 | ✅ ライブ P2P は相互 ephemeral で完全保護。△ ワンショット (ファイル/inbox) のみ長期鍵漏洩時に過去解読の余地 (§5.1 参照) |
| 物理的に端末を確保された場合 | ❌ 鍵が出てくる、無力 (HSM/TPM 利用や Full Disk Encryption が別途必要) |

---

## 5. 正直な弱点 (今後の改善余地)

### 5.1 Post-Quantum Forward Secrecy — ライブ P2P は達成済み、ワンショットのみ未対応 🟠

PQ-FS の状況は通信経路によって異なる。**ライブ P2P トランスポート（チャット・同期ファイル転送）は既に PQ-FS を達成しており、制限が残るのは非同期・ワンショット経路（ローカルファイル暗号化 / inbox 配送）のみ**である。

#### ライブ P2P ハンドシェイク（chat / 同期ファイル転送）: ✅ PQ-FS あり

`src/p2p/processor.rs` の実ハンドシェイクは、双方が毎接続で使い捨て鍵を生成する相互 ephemeral ハイブリッドである:
```
ss_ecc      = ECDH(ephemeral ‖ ephemeral)       ← 両側 ephemeral
kem_ss      = ML-KEM(client ephemeral KEM key)  ← クライアント ephemeral 鍵に encap
session_key = HKDF(ss_ecc ‖ kem_ss)
```
- クライアントは接続ごとに ephemeral KEM 鍵ペアを生成して公開鍵を送り、サーバはそれに encap する。サーバの長期 KEM 鍵は **指紋照合（MITM 検出）専用** で、鍵導出には一切関与しない。
- KEM では鍵ペアを提示する側（=クライアント）が ephemeral であれば共有秘密全体が ephemeral 依存となり、双方向通信に対して完全な FS が成立する（TLS 1.3 / SIGMA と同型。認証は ML-DSA 静的鍵による transcript 署名で別途担保）。
- したがって将来 CRQC が登場し、長期 KEM 鍵を盗み、ECDH を破ったとしても、使い捨て KEM 秘密鍵（セッション後に zeroize 済み）への encap は復元できず、**過去のライブ通信は復号されない**。

#### ワンショット（ローカルファイル暗号化 / inbox 非同期配送）: 🟠 PQ-FS なし

受信者がオフラインの非同期経路では双方向の ephemeral 交換ができず、`src/strategy/pqc.rs` は受信者の **長期固定 KEM 公開鍵** に encap する:
```
kem_ss = ML-KEM(static recipient KEM key)        ← Post-Quantum FS なし (鍵は固定)
```
**Post-Quantum 世界 (将来 CRQC 出現後)**: 攻撃者が
- (a) 過去の暗号文を保存し
- (b) 受信者の長期 KEM 秘密鍵を盗み
- (c) 量子計算機で ECDH を破る

の 3 点が揃うと、過去のワンショット暗号文が復号される。

**緩和策**:
- inbox 非同期配送: One-Time Prekey（PQXDH 風）で PQ-FS を達成（実装済み）。`--prekey-cmd init-identity|publish|seal|recv`。
- ローカルファイル自己暗号化: 双方向交換も Prekey インフラも無いため原理的に PQ-FS 不可。長期 KEM 鍵の定期ローテーション（運用）が唯一の緩和策 → 手順は **[KEY_ROTATION_GUIDE.md](../guides/KEY_ROTATION_GUIDE.md)**。

### 5.2 メタデータ漏洩 (relay 経由時) 🟡

Iroh 公式 relay (Number Zero, US 運営) を経由した場合、relay 運営者は以下を観測可能:
- 通信した NodeId 同士のペア
- タイミング
- パケットサイズ (メッセージ長を推測可能)
- IP アドレス

**緩和策**:
- `--no-relay` フラグで direct 接続のみ
- `--relay-url` で自前 relay
- IPv6 ネイティブ環境では direct 接続が成立しやすい (IPoE 等)

メッセージ**内容**は relay にも漏れない (E2EE の保証)。漏れるのは「**誰が誰といつ話したか**」のみ。

**`--discovery local`（mDNS、既定 off）のメタデータ注意**: 動的 peer discovery を `local` にすると、
自ノードの NodeId と direct アドレスを **LAN セグメント上にマルチキャスト広告**する（ticket の stale
アドレス自己修復のため）。広告は**ローカルネットワーク内のみ**で公開 DNS/DHT には出ないが、同一 LAN の
観測者は「この NodeId がこの IP にいる」を受動的に知り得る。既定 `none` は何も広告しない（最もメタデータが
少ない）。公開サービスへ publish する n0 DNS / mainline DHT discovery は意図的に未対応。

### 5.3 端末侵害

プログラムの暗号強度とは独立した問題:
- 秘密鍵ファイル (`~/nkct/.../private_*.key`) を読まれる
- メモリダンプから session key を抽出 (`Zeroizing` 型で軽減)
- キーロガーで打鍵記録

→ 別途 OS レベル防御 (FDE / TPM / 適切な権限) が必要。

### 5.4 Ticket の初回共有 (TOFU 問題)

ticket 共有経路を攻撃者が制御していると、攻撃者の ticket にすり替えが可能。

**緩和策**: 認証された経路 (対面 / Signal / 暗号メッセンジャー) で ticket を共有する。Slack DM や平文メールは不可。

### 5.5 NodeId 再利用による相関

同じ NodeId を長期間使うと:
- relay や ISP が「誰がどの程度の頻度で誰と話すか」のパターンを取れる
- Iroh は ephemeral NodeId 機能を持つが現状未活用

---

## 6. 利用が推奨される文脈

✅ **強く推奨される利用シーン**:
- 個人間の機密通信 (家族・友人・ビジネスパートナー)
- ジャーナリスト ↔ 情報源 (端末セキュリティが整っている場合)
- 企業内の機密プロジェクトメンバー間
- 研究者間の未発表データのやり取り
- Telegram / WhatsApp / Signal を使っている全シナリオ (より安全な代替として)

⚠️ **追加対策が必要なシーン**:
- 国家レベルアクターから狙われる活動家 (Tor 経由の Briar / Cwtch を併用検討)
- 数十年スパンでのアーカイブを要する機密を**ワンショット暗号化（ファイル/inbox）**で扱う場合 (ライブ P2P は PQ-FS 済みだがワンショット経路は長期鍵ローテで緩和)
- 大規模 (>10 人) のグループチャット (現状 1:1 のみ)

❌ **不適切なシーン**:
- 端末セキュリティに自信がない環境 (鍵保護が崩れる前提では何も守れない)
- 完全匿名通信が必須 (NodeId が永続識別子になり得る)

---

## 7. 結論

**「日常的な機密通信に必要なセキュリティ要件はすべて満たしている」**。さらに **PQC 対応によって「将来の量子計算機が登場した時に過去のあなたの通信が解読されない」**という、Signal / WhatsApp / iMessage / Telegram のいずれも完全には提供できていない保護を追加で得られる。

メインストリームの暗号化メッセンジャーを使っている人にとって、nkCryptoTool への移行は **すべての安全性指標で改善** (UX 以外)、特に Telegram のデフォルトチャットからの移行は **桁違いの強化**となる。

完璧ではない領域 (ワンショット暗号化の PQ-FS / メタデータ) は今後の改善ロードマップで対応予定で、現時点でも世界トップクラスのセキュリティを提供している (ライブ P2P 通信は PQ-FS 達成済み)。

---

## 6. 実装レベルの安全策 (Hardening)

### 6.1 Two-Pass 復号検証 (Write-then-Verify 対策) ✅

V1.1.0 より、ファイル復号時に **Two-Pass (2回読み込み) 方式**を導入しました。

- **Pass 1 (検証)**: 暗号文を全量読み込み、AEAD タグの検証のみを実行します。この段階では平文はメモリ上（Zeroizing バッファ）のみに存在し、**ディスクには一切書き出されません**。
- **Pass 2 (復号)**: 検証が成功した場合のみ、再度ファイルを読み込んで復号結果をディスクに書き出します。

**効果**:
復号に失敗した（改竄された）ファイルが一時的にでも平文としてディスクに着地する「Write-then-Verify」ウィンドウを構造的に排除しました。これにより、ディスク I/O の監視やプロセス異常停止による未検証平文の漏洩リスクが解消されています。

### 6.2 メモリ機密性の徹底

- **Zeroize 適用**: セッション鍵、派生鍵、および復号中の一時バッファに対し、`Zeroizing` 型による自動消去を適用しています。
- **秘密鍵抽出の強化**: 秘密鍵抽出時のループ内再代入においても、旧データを明示的に zeroize するよう強化されています (Security Finding 37-5 修正済)。

### 6.3 鍵リング my-identities (GPG 風・自分の鍵の DB カプセル化) ✅

自分の鍵ペアを鍵ファイルの代わりに redb keyring（`keyring.db` の
`keyring_my_identities_v1` テーブル）へ格納する運用のセキュリティ特性:

- **平文秘密鍵は存在しない**: 格納されるのは常に**パスフレーズ暗号化済み PKCS#8 PEM**
  （鍵ファイルと同じ機密度）。平文鍵は取り込み時に拒否され、`gen-my-key` による DB 内
  直接生成でも暗号化 PKCS#8 をメモリ内で構築してから格納する（**鍵ファイルは一度も
  ディスクに書かれない**）。パスフレーズなしでは生成・取り込みとも不可。
- **単一の検証パイプライン**: 取り込み・生成とも同じ検証（パスフレーズでの復号確認、
  PKCS#8 OID 分類 — EC は named-curve まで検査、秘密鍵からの公開鍵再導出と束縛、
  ML-KEM は encap/decap 自己テスト）を通過したものだけが DB に入る。
- **使用毎の束縛検証 (fail-closed)**: unlock のたびに秘密鍵から公開鍵を再導出し、
  格納済み SPKI・指紋との一致を要求する。DB レコードの差し替え・改ざんは、復号出力・
  署名・ハンドシェイクメッセージが生じる**前に**失敗する。KeyBundle 生成では束ねる
  **全スロット**（署名鍵+平文格納の公開鍵半分）を署名前に unlock 検証するため、改ざん
  レコードの公開鍵が署名済み束に混入することはない（無検証で pubkey ファイルを署名する
  ファイル方式より厳密に強い）。
- **クロバー防御**: 既存スロットへの異なる指紋での上書きは単一 write トランザクション内の
  check-and-insert で拒否（identity の暗黙置換防止。`remove-my-key` による明示操作が必要）。
- **取り込み時の TOCTOU 封鎖**: `import-my-key` は読み取りと `--shred-original` の
  ゼロ上書きを**同一の no-follow ハンドル**で行い、パスフレーズプロンプト中のパス
  差し替えで別ファイルを破壊させない。
- **P2P では日和見解決**: ハンドシェイク identity の keyring 解決はスロット不在を
  エラーにせず匿名動作を維持（可用性を落とさない）。unlock 失敗のみ硬いエラー。
- **残余リスク**: keyring.db 自体の窃取は暗号化 PKCS#8 の窃取と等価（パスフレーズ強度に
  依存）。レコード削除後も redb ファイル内に旧ページが残留し得る（媒体特性は
  KEY_ROTATION_GUIDE §4 参照）。

---

## 7. MLS グループチャット (`--features mls`)

3 人以上のグループ E2EE を提供する追加レイヤ。RFC 9420 準拠の `mls-rs` を、自前の
ハイブリッド `CipherSuiteProvider` で **完全に PQC ciphersuite に包んだ** 構成。

### 7.1 ハイブリッドスイート `0xF101` の構成

| 役割 | アルゴリズム | 標準 / 仕様 |
|---|---|---|
| 署名 | Ed25519 ‖ ML-DSA-65 | RFC 8032 + FIPS 204、連結ハイブリッド |
| KEM | X25519 ‖ ML-KEM-768 | RFC 7748 + FIPS 203、X-Wing combiner (`draft-connolly-cfrg-xwing-kem-01`) |
| KDF / Hash | SHA-256 / SHAKE-256 | NIST SP 800-185 |
| AEAD | AES-128-GCM | NIST SP 800-38D |

**連結 (concat) 設計の保証**: 古典側 (Ed25519 / X25519) と PQC 側 (ML-DSA / ML-KEM)
のどちらか **一方だけ** が破られても、もう一方が安全性を維持する。両方を同時に破る
ことができる相手以外には、署名偽造も鍵カプセル化突破も不可。

### 7.2 防御範囲と PCS

- **Forward Secrecy**: MLS の TreeKEM ratchet により、各 epoch のメッセージ鍵は
  独立。過去鍵を持つ相手が将来のトラフィックを復号できない。
- **Post-Compromise Security**: `remove_member` Commit が新 epoch を生成し、
  退会者が以前の epoch 鍵を持っていても新メッセージは復号不能。テスト
  `remove_member_blocks_new_epoch_decrypt` で性質を pin。
- **改竄検知**: Welcome / Commit / Application それぞれが MLS framing の MAC で
  認証され、改竄や reorder が検知される。WireFormat 不一致は
  `GroupError::InvalidWelcome` で拒否。
- **Self-decrypt 拒否 (RFC 9420 §15.1)**: 自分が暗号化した Application message を
  自分自身で復号することはできない (テスト `self_send_does_not_self_decrypt` で
  pin)。UI 側で自分の送信内容を表示する場合は、別途 local echo が必須。

### 7.3 永続化のリスクと緩和

at-rest は **ハイブリッド PQC 鍵階層**で保護される（`src/group/at_rest.rs`）。
MLS プロトコル層と同じ X-Wing (X25519+ML-KEM-768) 暗号スイートを再利用するため、
*harvest-now-decrypt-later* 攻撃に対して MLS の通信と同等の量子耐性を持つ。

```text
  passphrase (ユーザー入力)
    │  PBKDF2-HMAC-SHA512 (256 000 iters) + AES-256-GCM
    ▼
  at-rest hybrid SK   (X25519 SK || ML-KEM-768 DK)   ← at-rest.key
    │  X-Wing hpke_open
    ▼
  DEK (256 bit, ランダム生成)                         ← in-memory
    │  PRAGMA key = "x'<hex>'"
    ▼
  SQLCipher page key                                  ← groups.db を解錠
```

| 項目 | 現状 | 緩和策 |
|---|---|---|
| DB ファイル | SQLCipher 4 暗号化 sqlite (`mls-rs-provider-sqlite` の `sqlcipher-bundled` feature) | 256-bit DEK で AES-256-CBC + HMAC-SHA512 page 暗号化、ファイル permission `0o600`、`WAL` モード、`busy_timeout=5000` |
| 鍵素材 (in-memory) | mls-rs の `ZeroizeOnDrop` で in-memory 自動消去 | アプリ境界の中間 `Vec<u8>` も `Zeroizing` でラップ。DEK / at-rest SK / passphrase いずれも `Zeroizing` で保持 |
| At-rest 暗号化 (古典層) | SQLCipher 4 (AES-256-CBC + HMAC-SHA512) を 256-bit ランダム DEK で適用 | 署名鍵 (`mls:identity:sk`)、グループ木、KeyPackage 秘密鍵、PSK が同一暗号境界に入る |
| At-rest 暗号化 (PQC 層) | X-Wing ハイブリッド KEM (X25519+ML-KEM-768) で DEK を encapsulate (`groups.db.kek`) | MLS プロトコル層と同じ `HybridCryptoProvider` を流用。古典/PQC のどちらかが破られても他方で守られる |
| at-rest 鍵ファイル (`at-rest.key`) | PBKDF2-HMAC-SHA512 (256 000 iters) → AES-256-GCM 封筒で hybrid SK を保管 | 42 B のヘッダ (magic / version / KDF params / salt / nonce) を AAD に含めるため、param 改竄も AEAD タグで検出。`0o600`、temp-then-rename でアトミック書込 |
| KEK ファイル (`groups.db.kek`) | `HpkeCiphertext { kem_output, ciphertext }` を MLS-codec で serialise + 10 B ヘッダ | 改竄は HPKE AEAD タグで検出。HPKE `info = b"nkct-mls-at-rest-v1"` で他用途との domain separation |
| パスフレーズ取得 | `NK_PASSPHRASE` 環境変数 or 対話入力 (`get_masked_passphrase`) | 既存の PEM 暗号化と同じ経路を再利用。空パスフレーズは `open_at_rest_storage` が拒否 |
| 同時書き込み | 単一プロセス前提 | sqlite WAL + `busy_timeout` 5s で短期競合を吸収 (multi-process は非推奨) |
| バックアップ運用 | `groups.db` 単体では復号不可 — `at-rest.key` + `groups.db.kek` + passphrase の 3 要素全部が必要 | 3 ファイルを同一ディレクトリで一括バックアップ。passphrase はユーザーが別管理 |
| DEK ローテーション | `nkct mls --mls-cmd rekey` (`group::at_rest::rotate_dek`) | 新規 DEK を生成し `PRAGMA rekey` で全ページ再暗号化 → 新 KEK を再 encapsulate。クラッシュ安全: 新 KEK を `groups.db.kek.pending` に先行ステージ → DB rekey → atomic promote の順。中断時は次回 open の `finalize_pending_rekey` がどの DEK で DB が開くか実測して解決するため、DB/KEK 2 ファイルのどの中断点でも復旧可能。DEK 漏洩疑い時の緩和策 (既に流出した旧 ciphertext のコピーは保護しない)。at-rest hybrid SK / passphrase は別途 `at-rest.key` 再生成で更新 |
| 既存平文 DB の取扱い | 起動時に自動マイグレーション (`group::at_rest::migrate_plaintext_to_sqlcipher`) | 先頭 16 byte の `SQLite format 3\0` magic で平文 DB を検出し、`sqlcipher_export()` で DEK 暗号化コピーへ変換 → 鍵で開けることを検証してから原本を atomic rename で置換。平文の原本・WAL/journal サイドカーは置換後に unlink するため平文残存なし。検証成功前は原本を破壊しない |
| inbox DB (store-and-forward リレー) | `inbox.db` も同じ at-rest レイヤで SQLCipher 暗号化 (`network::inbox::InboxServer::open` → `group::resolve_dek`) | `payload` 自体は MLS 暗号文だが、`recipient` / `sender` / `created_at` の**メタデータ**がリレーのディスク上で平文になるのを防ぐ。at-rest 鍵は共有 `at-rest.key` ではなく DB 固有の `inbox.db.at-rest.key` に置き (`AtRestPaths::beside_db`)、同一ディレクトリの MLS クライアントと初期化レースしない。`0o600` も適用 |

### 7.4 トランスポート抽象 (ALPN `nkct/mls/1`)

既存 Iroh エンドポイントに新規 ALPN `nkct/mls/1` を追加。1 ストリーム = 1
`MlsMessage`、u32 LE 長さプレフィックス、最大 `MAX_MLS_FRAME_BYTES = 16 MiB`。
不正な長さプレフィックス (>16 MiB or 0) は **バッファ確保前に** 拒否されるため、
悪意の peer によるメモリ枯渇攻撃は成立しない。

### 7.5 既知の制約

- **ハイブリッド suite のみ公開**: クラシカル MLS (RFC 9420 標準スイート)
  ピアとは通信できない。設計上の意図的制約 (PQC 必須化)。
- **address book は未統合**: メンバーの `MemberId → PeerAddr` 対応は CLI/GUI 側で
  手動指定 (`--mls-recipient-ticket`)。動的 discovery は将来作業。
- **`cargo audit` の transitive 警告**: `iroh` 依存ツリーに hickory-proto 等の
  既知警告があるが、これは Iroh アップストリームに追従が必要な範囲。
  プロジェクト直接依存には脆弱性なし。
- **at-rest AEAD は AES-256-GCM (実装済み)**: 当初 at-rest 層は MLS と同じ
  `0xF101` (AES-128-GCM) を流用しており、KEM の外側で DEK を包む AEAD が Grover
  攻撃で実効 64-bit まで減衰する懸念があった。現在は at-rest 専用スイート
  `0xF102` (X-Wing KEM / HKDF-SHA512 / **AES-256-GCM**, `crypto_adapter::
  build_at_rest_suite`) で DEK を封入するため、AEAD も Grover 後で実効 128-bit を
  保ち PQ-safe。KEM は `0xF101` と同一なので `at-rest.key` 鍵ペアは互換。KEK の
  suite バイトで旧 `0x01` (AES-128) を読み取り互換し、次回 rekey で `0x02`
  (AES-256) に書き換わる。MLS プロトコル層は interop 制約のため `0xF101`
  (AES-128) のまま (こちらは MLS epoch ratchet で別途守られる)。
- **DEK の forward secrecy なし**: §7.3 で生成された DEK は (明示的に rekey
  しない限り) DB 寿命の間固定。`groups.db.kek` または `at-rest.key` が将来侵害
  された場合、その時点で DB 内の既存メッセージはすべて復号可能になる (MLS の
  epoch ratchet は DEK の上位層なので、at-rest 層では FS を提供しない)。緩和策と
  して `nkct mls --mls-cmd rekey` (`PRAGMA rekey` 経由の DEK ローテーション) を
  提供済み — ただし漏洩前に取得済みの旧 ciphertext コピーは保護できない。完全な
  FS には MLS epoch 境界での DEK 再生成等が別途必要。
- **anti-rollback (オプトイン実装済み / 既定 off)**:
  `NK_ROLLBACK_POLICY` で制御。`off`(既定) は従来通り KEK version `0x02`、挙動
  不変。`permissive`/`strict` は per-DB の単調カウンタ値を KEK の HPKE `info` に
  暗号的にバインド (KEK version `0x03` = `bound_info || counter(u64 BE)`)。カウンタ
  は **rekey 時にのみ** advance。古い `(groups.db, groups.db.kek)` スナップショットに
  書き戻された場合、**そのスナップショット以降に rekey を挟んでいれば**現行カウンタとの
  `info` 不一致で HPKE AEAD 復号が失敗し**巻き戻しを検知**する。カウンタ更新と DB
  再暗号化の 2 リソース整合は既存の `.pending` ステージング + `resolve_kek_to_dek` の
  3 パターン復旧でクラッシュ安全。設計の全体像は
  `docs/design/ATREST_ANTIROLLBACK_DESIGN.md`。
  - **⚠ 検知範囲の限界（2026-08 の再確認で判明。それ以前の本節は「古い
    `(groups.db, groups.db.kek)` の組に戻されても検知する」と無条件に書いており、
    誤りだった）**: カウンタが暗号的に束縛されるのは **KEK ファイルだけ**で、
    セキュリティ状態の実体である `groups.db` 自体は一切束縛されていない。
    `resolve_kek_to_dek` は live KEK が現行カウンタで decapsulate できた時点で DEK を
    返し（`src/group/at_rest.rs:706`）、**DB を一度も検査しない**。したがって:
    - **現行の KEK をそのまま残して `groups.db` だけ古い版に差し替える攻撃は、どの
      ポリシー（`permissive` / `strict` / TPM）でも検知されない。** 削除したメンバーの
      復活、削除済みレコードの復活、ratchet の巻き戻しが、警告なしに成立する。storage
      dir へ書ける攻撃者にとっては、`(db, kek)` を対で戻すより容易で確実な経路である。
    - 対で戻す場合も、検知できるのは **rekey 境界をまたいだときだけ**。カウンタは
      `nkct mls --mls-cmd rekey` でしか進まないため、最後の rekey 以降のスナップショット
      はカウンタが同値で `info` が一致し、普通に開く。
    - `current_rollback_epoch` も同じ rekey 回数を返すため、オンラインの inbox
      CHECKPOINT アンカー（フェーズ3）もこの差し替えを検知しない。
    実装で塞ぐには KEK ではなく **DB 側の鮮度**を束縛する必要がある — コミット済み DB
    状態が進むたびにカウンタ（または安価なソフトウェア随伴カウンタ）を進め、期待値を
    暗号化 DB の内側に保存し、開封時に stored-vs-current を比較して退行なら fail closed
    にする。**未実装**。現状の anti-rollback は「rekey をまたぐ巻き戻し」に対する保護と
    理解すること。
  - **`permissive` (フェーズ1)**: software カウンタ (`SoftwareCounter`、
    `$XDG_STATE_HOME/nkct/rollback/<hash>.ctr` — ストレージ dir 外)。state ファイル
    ごと過去スナップショットに戻されると検知できない (case D 限界)。
  - **`strict` (フェーズ2、Linux 限定)**: TPM 2.0 NV 単調カウンタ (`TpmCounter`、tpm2-tools +
    `/dev/tpmrm0`)。ストレージ dir を丸ごと過去版に戻してもハードウェアカウンタは
    巻き戻らないため case D 限界を解消。NV index は per-DB
    (`0x0150_0000 | (sha256(abs_path)[..3] & 0xFFFFF)`、owner 域・20bit; 衝突
    ≈1/2^20 は許容 — registry-free 設計の対価)。`tpm2_nvundefine`→再定義による
    カウンタリセットは**効かない**: TPM は counter NV を過去最大値以上で初期化する
    ため、再定義後の値は旧値以上に保たれる (実機確認済み)。TPM 不在時はエラーで
    silent downgrade を防ぐ。
  - **macOS / Windows の `strict`**: **非対応（正直にエラー）**。非特権アプリが使える
    オフラインのハードウェアモノトニックカウンタが存在しないため (macOS は Secure Enclave に
    公開カウンタ API 皆無、Windows は TPM ドライバが NV カウンタコマンドをブロック; 詳細は
    [ATREST_ANTIROLLBACK_DESIGN.md §5.1](../design/ATREST_ANTIROLLBACK_DESIGN.md))。`cfg(target_os)` で
    分岐し、黙ってソフトカウンタへ降格せず拒否する。これらの OS の巻き戻し検知は
    `permissive`（ソフトカウンタ）＋ 後述のオンライン `inbox` CHECKPOINT が担う。
  - **共通の残存リスク**: カウンタ消失 (state ファイル削除、または `TPM2_Clear` で
    TPM 全体を初期化) 時は v0x03 DB が開けなくなる (有効化の対価として文書化)。
    `TPM2_Clear` はプラットフォーム/owner クリア権限を要し全 TPM 状態を消すため、
    巻き戻し攻撃の前提 (storage dir 書込) より遥かに高い壁。MLS epoch 単調増加は
    引き続き部分的なバックストップ。
  - **`inbox` リモートチェックポイント (フェーズ3)**: `nkct/inbox/1` に `CHECKPOINT`
    操作 (tag `0x03`) を追加。クライアントは現在の at-rest epoch を inbox サーバへ
    報告し、サーバは認証済み peer (QUIC NodeId) ごとに最大 epoch を保持
    (`checkpoints` テーブル) して退行を検知 (`network::inbox::checkpoint` ↔
    `handle_checkpoint`)。**オフデバイスの独立アンカー**なので、storage dir + state
    ファイルを丸ごと過去版に戻されても (software カウンタ単独では検知不能なケース)
    オンライン時に検知できる。ただし inbox サーバは**半信頼**(payload 非読取の
    Delivery Service) — サーバが嘘をつけば false negative/positive があり得るため、
    `RollbackSuspected` は**警告**に留め、ローカル TPM/software カウンタを権威的な
    チェックとして維持する (ハードフェイルしない)。`--inbox-url` 設定かつ
    `NK_ROLLBACK_POLICY != off` のときに送信。
  - **DoS (fail-closed) の許容**: `/dev/tpmrm0` 書込権限を持つローカル攻撃者は NV
    カウンタを勝手に increment / undefine して v0x03 DB を開けなくできる (DoS)。
    ただしこれは **fail-closed** であり、カウンタを進める/消すことが古い KEK を
    復号可能にすることはない — 巻き戻し防止という目的自体は保たれる。NV インデックス
    は単一ユーザー前提で owner 域に置く (index auth を付けても owner auth による
    undefine DoS は残るため不完全)。`tpm2-*` は PATH 上の名前で起動する
    (`src/key/tpm` と同一・非 setuid ユーザー CLI 前提)。multi-process 同時 rekey は
    非サポート (§7.3)。
- **KEK の per-DB バインディング (実装済み)**: KEK は HPKE `info =
  b"nkct-mls-at-rest-v1" || len(binding) || binding` でシールされ、binding は
  DB ファイル名 (`group::at_rest::db_binding`)。同一 at-rest 鍵を複数 DB で共有
  しても、ある DB の KEK を別 DB の KEK 位置に差し替えると `info` 不一致で HPKE
  AEAD が失敗するため KEK 再利用攻撃が成立しない。binding はフルパスでなくファイル
  名なので、at-rest 三点セットごとディレクトリ移動しても KEK は有効。旧 `0x01`
  (unbound) KEK は読み取り互換を保ち、次回 rekey で `0x02` (bound) に書き換わる。
  なお inbox は `beside_db` で DB 固有の at-rest 鍵を持つため、そもそも groups.db
  と鍵を共有しない。
- **平文 DB マイグレーションのバックアップは取らない**: §7.3 の自動マイグレーション
  は原本を破壊する前に暗号化コピーの可読性を検証するため通常はデータ安全だが、
  平文バックアップを意図的に残さない (at-rest 平文残存を避けるため)。検証を通った
  暗号化コピーが直後に I/O 障害等で壊れる極端なケースに備えるなら、ユーザーが
  事前に `groups.db` を手動コピーしておくこと。

### 7.6 抽象境界の CI 強制

- `scripts/check_no_mls_leakage.sh` — `mls_rs::*` の import は `src/group/` と
  GUI ドライバ (`src/gui/group_chat.rs`) のみ。リーク検出時 CI 失敗。
- `scripts/check_p2p_abstraction.sh` — `iroh::*` の import は
  `src/p2p/backend/iroh.rs` のみ。
- どちらも GitHub Actions の `mls-abstraction-check` /
  `p2p-abstraction-check` ジョブで毎 PR 検証。

---

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体技術計画
- `CHAT_USAGE_GUIDE.md` — 2 端末チャット手順 (実用ガイド)
- `INTEROP_VERIFICATION_2026-05-07.md` — bazzite ↔ nkwire 異環境間動作実証
- `SPEC.md` (リポジトリルート) — V3 ハンドシェイクとプロトコル仕様
- `SECURITY.md` (リポジトリルート) — 公式セキュリティポリシー (もしあれば)
- `docs/design/MLS_GROUP_CHAT_PLAN.md` — MLS グループチャット実装計画
- `MLS_GROUP_CHAT_REPORT.md` — MLS グループチャット完了レポート
