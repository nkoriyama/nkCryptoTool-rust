# 公開鍵授受(ML-DSA 単一アンカー) — バイトフォーマット確定版【FROZEN / 実装前レビュー済み】

ステータス: **フェーズ2 完了（バイト凍結）。レビュー指摘を全反映済み。フェーズ3 増分1(ctx 配線)=PR #24。**
対応: ブリーフ `nkct-key-exchange-brief.md` §3–§6。凍結前提(下記 §2)は確認済みで確定。

> **【凍結後の訂正 — 指紋 `nkct-id-v1` 前置を撤回】** フェーズ3 増分2 の着手前調査で、指紋前置は**便益ゼロ**（識別子には同名前空間に分離相手が無く、署名材料になる2箇所=binding/prekey は署名層 ctx で分離済み＋生鍵が安全性を担う冗長フィールド）と確定。指紋は `SHA3-256(raw)` のまま不変とする。**署名 ctx 分離（§2/§11、増分1 でロック）は署名側の別機構で無傷** — 撤回対象は指紋 hash の前置のみ。詳細と却下した代替は §3.1、移行への波及は §7(B)。副産物として既存 allowlist/ticket/peer_id/binding が全生存し増分2 は非破壊化。

## 決定サマリ（レビュー回答 Q1–Q5）
- **Q1 = flag day**（ALPN bump）。ctx="" の旧検証パスを1本も残さない。version ネゴ(b)は不採用。
- **Q2 = 【撤回】**。ハードカットオーバーは §3.1 の `nkct-id-v1` 前置撤回により**不要**（指紋不変→既存 allowlist 生存）。§7(B) 参照。当時の判断（(ii) 旧破棄+電話再確認）は指紋スキーム変更を前提にしたもので、変更が消えたため moot。
- **Q3 = 4つ目ラベル `nkct-bundle-v1` を新設 approve**（4ラベル全相異・prefix-free）。
- **Q4 = #7 発火は明示モード選択**（pin 有無から暗黙推論しない）＋presence フラグ(#5拡張)でワイヤ決定的。
- **Q5 = native ML-DSA ctx で凍結**。OpenSSL 3.6.2 が context-string param 対応を実地確認済み。byte-prefix fallback は不要。

---

## 0. §0 調査で確定した事実（前提）
- ハンドシェイク署名は両側署名・相互検証。被覆は非対称: initiator=#1–6、responder=#1–11。**initiator が responder identity を cross-bind していない**のが唯一の実ギャップ。
- `pqc_sign(.., None)` の `None` は `_passphrase`（未使用）。実署名 `fips204 try_sign(msg, &[])`＝**FIPS 204 ctx が空**。OpenSSL(`EVP_DigestSign`)も ctx 未設定＝空。
- 指紋=`SHA3-256(raw_pub)`、ドメイン前置なし。canonical=raw（wire も raw、pin 比較で SPKI→raw）。
- allowlist = **hex SHA3-256 hash のみ保持**、pubkey 非保持 → prefix 再計算不可。
- `allow_unauth`＋指紋無しの **node_id-only ピン無し接続経路が実在**。
- ML-DSA-65 pub=1952B/sig=3309B、ML-KEM-768 ek=1184B。

---

## 1. エンコード規約
- **LP**: `u32 little-endian 長さ ‖ bytes`（既存 v3 wire）。可変長 pubkey/ct/sig。
- **raw**: 固定長・前置なし。NodeId=32B、flags=1B、指紋=32B。
- **u64_be**(unix秒) / **u16_le**(count)。
- **canonical pubkey = raw アルゴリズムバイト**。署名対象・hash 入力・pre-commit 比較の全てで raw。SPKI は署名/hash 対象に入れない。

---

## 2. ドメイン分離ラベル【FROZEN = native ML-DSA ctx】

**署名ラベルは ML-DSA(FIPS 204) native context string に入れる（byte-prefix は使わない）。**
FIPS 204 は内部で `M' = 0x00 ‖ IntToBytes(|ctx|,1) ‖ ctx ‖ M` と符号化。native は先頭 `0x00` ドメインバイトが入るため、手動 byte-prefix とは**別メッセージ表現**になる ── どちらを採るかは KAT が pin するバイト列を決めるので、ここを先に凍結する必要があった。

**凍結前提の確認結果（実地）**: OpenSSL 3.6.2 が `-pkeyopt context-string:` で ML-DSA-65 署名を生成（3309B）＝context-string param 対応を確認。fips204 は `try_sign(msg, ctx)` 対応。両者 FIPS 204 準拠 → 同一 ctx で相互運用可。→ **native ctx で確定、fallback 不要。**

実装差分(フェーズ3): `pqc_sign`/`pqc_verify` に `ctx: &[u8]` を追加配線。rustcrypto=`try_sign(msg,ctx)`/`verify(msg,sig,ctx)`、openssl=`EVP_DigestSignInit_ex`＋`OSSL_PARAM octet_string("context-string", ctx)`。

### 2.1 全ラベル割当（identity 鍵を共有する全 native-ctx 文脈を prefix-free 分離）
| 文脈 | ラベル | 機構 |
|---|---|---|
| **iroh** handshake 署名 | `nkct-handshake-iroh-v1` | ML-DSA ctx |
| **TCP** handshake 署名 | `nkct-handshake-tcp-v1` | ML-DSA ctx |
| prekey 署名(PQFS) | `nkct-prekey-v1` | ML-DSA ctx（**byte-prefix から統一移行**、§11） |
| keybind 署名 | `nkct-keybind-v1` | ML-DSA ctx |
| bundle self_sig | `nkct-bundle-v1` | ML-DSA ctx |
| 指紋 | （前置なし） | `SHA3-256(raw)`。**`nkct-id-v1` 前置は撤回**（§3.1）— 識別子には分離相手が無く、署名材料箇所は署名層 ctx で分離済み |

**iroh と TCP は別ラベル**: 同一 identity 鍵・同一 transcript フォーマットのため、**同一 ctx だと cross-transport replay**（iroh sig を TCP に差す/逆）が生じる。ctx を分けると FIPS 204 の M' が別空間になり塞げる。**transcript(#1–#12)のバイトは一切変えない**（ctx は M' 前置でメッセージ本体でない）。

**不変条件**: 移行後、identity 鍵で**空 ctx 署名する native-ctx 文脈を1本も残さない**。5 署名ラベルは全相異かつ prefix-free。唯一 ctx="" に残すのは file 署名のみ（§11、孤立により分離）。（指紋は署名 ctx ではなく識別子 hash であり、この不変条件の対象外。指紋前置 `nkct-id-v1` は撤回＝§3.1。）

---

## 3. 指紋（§3.1）【`nkct-id-v1` 前置は撤回 — 指紋は前置なし】
```
fingerprint = SHA3-256( mldsa_pk_owner_raw )      // 32 bytes, full。ドメイン前置なし
```
- 切り詰め禁止（full 256bit、下限128bit）。canonical=raw。
- 電話読み上げ: PGP wordlist（偶数/奇数交互、32B→32語）＋チェックワード1語。指紋と bundle 表示で同一 wordlist。

### 3.1 【撤回】`nkct-id-v1` 前置を仕様から落とす（凍結後・フェーズ3 増分2 着手前の訂正）
凍結時は指紋を `SHA3-256("nkct-id-v1" ‖ raw)` とドメイン前置していた。増分2 着手前調査で、この前置は**便益ゼロ**（コスト高ではなく便益無しが決め手 — 外部利用者ゼロで大鉈は可、コストは decision driver でない）と確定したため撤回する。

- **識別子用途**（allowlist / routing peer_id / group id / ticket pqc_sign_fp）: 同一名前空間に流れ込む「別種の hashed 識別子」が存在しない（比較先は常に同型の pubkey 指紋、入力は固定長の型付き pubkey）。**前置が分離する相手が居ない** → 便益ゼロ。分離便益は将来「別種の識別子を同名前空間に足す」時にしか生じず、それは作らないと決めた future-proofing scaffolding。第二原像(2^256)・replay は前置有無で不変。
- **署名材料用途**（`pqc_sign` 全呼出し棚卸しの結果、指紋が署名される材料に入るのは `group/binding.rs` と `prekey.rs` の**2箇所のみ**、実地確認済み）: いずれも
  - (1) その署名層自身の ctx（`nkct-mls-transport-binding-v1` の `BINDING_CONTEXT` / `nkct-onetime-prekey-v1` の `PREKEY_SIG_CONTEXT`）で**既に分離済み**、
  - (2) 指紋は**生 pubkey と並んで**署名される冗長フィールド — binding は raw `transport_pub` を lp 付きで同梱し安全性（POP・epoch・MLS 鍵コミット）は生鍵が担う／prekey は検証鍵 `dsa_pub` 自身から `peer_id` を導出し同じ鍵で署名検証（鍵と不一致になり得ない導出値）。

    → 署名側の domain-sep は署名層 ctx が担い、指紋 hash の前置は**冗長** → 便益ゼロ。指紋は KDF salt/info・MAC 鍵にも使われない（`SHA3-256` の salt 用途は transcript 上＝別入力）。
- **却下した代替**:
  - (a) **pin だけ前置** = pin 指紋 ≠ routing peer_id / MLS binding fp / group id に割れる。これらは `SHA3-256(dsa_pub)` として**意図的に同一値・load-bearing に統一**されている（`prekey.rs` L79-84・`group/binding.rs` L125-131・`processor.rs` L580 のコメントが明言）。割ると新規 misbinding 面を自分で開ける **security-negative** → 却下。
  - (b) **全箇所前置** = 統一は保つが無便益 churn ＋ `nkct-id-v1` バイトを全サブシステムの interop 面に焼き付ける純損 → 却下。
- **安全不変条件は不変**: 前置は versioning/future-proofing の scaffolding であって invariant ではない。ロック済みの**署名 ctx 分離（§2/§11、増分1）は署名側の別機構で無傷**。§4.2 A/B・cross-transport replay のどれにも前置は load-bearing でなかった。「scaffolding は落とす、invariant は保つ」に収まる。
- **副産物（増分2 の非破壊化）**: 指紋値が `SHA3-256(raw)` のまま**不変** → 既存 allowlist・ticket・inbox peer_id・MLS binding・group id が全生存。**増分2 は「破壊的再ピン」から、known_peers への検証状態（verified/unverified）additive スキーマ進化＋指紋 wordlist 表示に格下げ**（非破壊）。§7(B) 参照。

---

## 4. ハンドシェイク署名 修正（§4.1）— **#5 を flags 化して #7 presence をワイヤ決定的に**

> **【スコープ = iroh handshake 専用】** §4.1–§4.4 は **iroh（`p2p/processor`）** の握手を規定する。凍結時この §4 は暗黙に iroh 構造（単一 TranscriptBuilder で responder が #1–#12 を連続署名、node_id #1/#2 あり）を前提にしていた。実コード照合（増分3 着手前）で **TCP（`network/tcp`）は構造が異なる**ことが判明: (1) node_id #1/#2 が無い（raw socket）、(2) `server_transcript` は client transcript の連続だが **server_dsa_pub/static KEM を署名バイトに含めない**（server pub は検証鍵としてのみ）。よって §4 を TCP にそのまま適用できない。**TCP は §4.5 に分離**し、独立の増分3b として §0 相当の被覆マトリクス調査を先に行う。iroh 増分3 に TCP を混ぜない（未調査の被覆設計が clean な iroh 修正に相乗りしレビュー単位が濁るため）。

### 4.0 【凍結前修正】presence フラグ
旧 #5 は「initiator 自己 auth」1 ビットで #6 のみ支配。**#7(responder 認証要求)は独立ビット**なので #6 から導けず、presence が非決定になる（フィールドずらし曖昧性）。→ **flags バイトに拡張**。ゼロ埋め常時送出は「全ゼロが有効鍵か」問題を招くため presence ビット方式。

- **#5 = initiator flags (raw1)**: `bit0(0x01)=initiator_self_auth`→#6 支配、`bit1(0x02)=expects_responder_auth`→#7 支配。他ビットは reserved(=0、検証で拒否)。
- **#10 = responder flags (raw1)**: `bit0=responder_self_auth`→#11/#12 支配。他 reserved。

両 flags は署名対象内・#6/#7・#11/#12 より前に置く → responder は #5 を先読みして #6/#7 のパスを決定的に決める。

### 4.1 凍結 transcript
**initiator 署名対象（#1–#7）:**
| # | フィールド | enc | 条件 |
|---|---|---|---|
| 1 | nodeid_A (initiator) | raw32 | 常時 |
| 2 | nodeid_B (responder, transport) | raw32 | 常時（node_id 束縛は残す） |
| 3 | initiator P-256 eph | LP | 常時 |
| 4 | initiator ML-KEM pub | LP | 常時 |
| 5 | **initiator flags** | raw1 | 常時（bit0→#6, bit1→#7） |
| 6 | initiator ML-DSA pub | LP | #5.bit0 |
| 7 | **expected responder fingerprint** | **raw32** | **#5.bit1** |

**#7 = expected responder fingerprint（raw32 = `SHA3-256(mldsa_pk_responder_raw)`、前置なし＝§3 撤回後の素の指紋）。** 凍結時は「expected responder ML-DSA pub(LP)」だったが、実コード照合で修正: initiator が responder の **full pub を持つのは `--signing-pubkey` 時だけ**で、ticket 経路では `target_sign_fp`（指紋）しか持たない → full pub の #7 を構築できず、A-resp が「full pub を持つモード限定」の部分適用になる（§4.4 で潰したはずの「モードで穴が開く」の再来）。**#7 を pin 指紋(raw32) にすれば全モードで常時構築可** → A-resp が全モードで成立。指紋は §3 で確定した「唯一の統一識別子（pin==routing==binding==group が同一値）」であり、#7 を full pub にするとその体系内で #7 だけ pub 実体を持つ異物になる。指紋に揃えるのが体系的にも正しい（transcript 32B vs 1952B 削減は副次）。
- **不変条件(a) canonical hash 一致**: initiator が pin から取り出す #7 の 32B と、responder が `SHA3-256(own_pub_raw)` で作る 32B が **同一の `SHA3-256(dsa_pub_raw)` 定義**（前置なし、canonical=raw）で一致すること。#7 だけ別 hash 定義になると照合が無言で落ちる。
- **不変条件(b) responder 再導出**（§6.2 と同じ discipline）: responder は受信 #7 を**信頼の入力にせず**、自ら `SHA3-256(own_pub_raw)` を計算して #7 と**比較する標的**として扱う（増分4 prekey 再導出ガードと同型）。

→ `sig_I = ML-DSA-Sign(sk_I, msg=transcript[#1..#7], ctx=HANDSHAKE_CTX)`
（`HANDSHAKE_CTX` = iroh なら `b"nkct-handshake-iroh-v1"` / TCP なら `b"nkct-handshake-tcp-v1"`。transcript バイトは共通・不変、ctx のみ transport で分岐 = cross-transport replay 封じ）

**responder 署名対象（#1–#12、同一 builder の続き）:**
| # | フィールド | enc | 条件 |
|---|---|---|---|
| 8 | responder P-256 eph | LP | 常時 |
| 9 | ML-KEM ct | LP | 常時 |
| 10 | **responder flags** | raw1 | 常時（bit0→#11/#12） |
| 11 | responder ML-DSA pub | LP | #10.bit0 |
| 12 | responder 静的 ML-KEM pub | LP | #10.bit0 |

→ `sig_R = ML-DSA-Sign(sk_R, msg=transcript[#1..#12], ctx=HANDSHAKE_CTX)`（同 transport の ctx）
→ salt = `SHA3-256(transcript[#1..#12])` → HKDF。

### 4.2 双方向 cross-check【照合が binding の本体 — 両側で一級不変条件】

**責務は対。含める側(pre-commit)と検証する側(pin 照合)の両方が無いと片肺で misbinding が裏口から復活する。**

**(A-resp) responder 側**: initiator 署名(#1–#7, ctx=handshake)検証後:
```
if #5.bit1 (expects_responder_auth):
    assert #10.bit0 == 1                              // responder が実際に自己署名する
    assert #7 == SHA3-256(own_mldsa_pk_raw)           // 自ら再導出した指紋を #7 と照合(不変条件 b)
    不一致/不在 → abort（identity-misbinding / downgrade）
```
（#7・own 指紋とも §3 の素の `SHA3-256(dsa_pub_raw)`＝不変条件 a。responder は #7 を信頼せず own_pub から再導出した値を標的に比較＝不変条件 b。）

**(A-init) initiator 側【第一級不変条件 — downgrade の副次記述ではない】**:
**responder 署名 sig_R は「ピン済み identity」に鎖して検証する。wire の #11 をそのまま信頼して検証してはならない。**
```
if #5.bit1 (expects_responder_auth):
    // pin 照合は sig 検証より前。全 identity 入力経路で保証すること:
    if target_sign_fp あり:   assert SHA3-256(#11) == target_sign_fp
    if signing_pubkey あり:   assert #11 == pinned_raw_pub
    （将来 bundle 由来 pin 等の追加経路も同様に sig 検証前に照合。どれか1本でも抜けると A-init が片肺）
    verify(sig_R, msg=transcript[#1..#12], pk=#11, ctx=handshake) が成功
    いずれか不成立 → abort
```
- **攻撃**: MITM M が responder になりすまし、#11=M_pub・sk_M で sig_R を作る。initiator が **wire の #11 で sig_R を検証してしまうと通過し、initiator は M を P(ピン)と誤信**する。全体で閉じたはずの misbinding が検証鍵の取り違えで復活する。
- 塞ぎ: pin 照合（`SHA3-256(#11)==target_sign_fp` ／ `#11==pinned_raw_pub`）を **sig 検証の前**に **MUST** で強制（#11 は冗長フィールド）。§6.2(bundle owner=pin 済み値で検証)と完全対称。
- **現状コード = A-init は既に実質存在**（`p2p/processor` client: target_sign_fp 経路 881–885・signing_pubkey 経路 875 が sig 検証 895 の前）。増分3 はこれを「**全 identity 入力経路で pin 照合が sig 検証前に走る**」不変条件へ格上げして明示化し、**同一コミットで #7 pre-commit（A-resp）と対にする**（片肺禁止）。

node_id(#2) と ML-DSA identity(#7/#11) の**両方**を束縛 → node_id↔identity 不一致自体がシグナル。

### 4.3 auth モードマトリクス【明示モード選択】
trust/anonymous は**呼び出し側の明示選択**（pin 有無から暗黙推論しない）。

| initiator_self_auth(#5.b0) | expects_responder_auth(#5.b1) | responder_self_auth(#10.b0) | 挙動 |
|---|---|---|---|
| 1 | 1 | 1 | 相互認証。initiator が #7 pre-commit → responder が §4.2 照合。responder 署名が #6 を cross-bind |
| 0 | 1 | 1 | initiator anonymous・responder 認証。#7 pre-commit + §4.2 照合は残す |
| 1 | 0 | 0/1 | responder 認証せず。#7 無し。responder 認証を要求しないので pre-commit 不要 |
| 0 | 0 | 0 | 完全 anonymous・信頼確立せず |

**downgrade 検出（文言精密化）**: 「flag=0 を署名内で見て弾く」ではなく、**initiator が responder 認証を要求（#5.bit1）した場合、pin に鎖する有効な responder 署名(ctx=handshake, fingerprint(#11)==pin)が来ない/一致しないことで abort**。要求した署名の不在で弾くのが実態。

### 4.4 ピン無し接続を塞ぐ【fail-open 防止】
- **明示的に responder を認証するモード(#5.bit1) で target identity のピンが無い場合は接続拒否**。#7 を空/欠落のまま握手続行しない。
- 「pin 無し → 黙って anonymous に落ちる」を禁止（pin 不在自体を downgrade ベクタにしない）。
- TOFU 無し: 未検証初回接続を信頼する経路 0 本。既存 `allow_unauth`＋指紋無しの node_id-only 経路は trust モードで到達不能に。

### 4.5 TCP handshake【増分3b に分離 — 着手前に §0 相当の被覆調査が必須】
TCP（`network/tcp`）は iroh と構造が違うため §4.1–§4.4 をそのまま適用できない。**増分3(iroh)には混ぜず、独立した増分3b**として扱う。増分3b の**入口で必須の調査**（iroh の増分3 で確立したパターンを持てる分、軽くなる）:
- **被覆マトリクス(field×方向)を TCP について一から埋める**（§0 を iroh でやったのと同じ作業）。特に「**server 署名が何を被覆しているか**」。現状 `server_transcript` は client transcript の連続だが **server_dsa_pub/static KEM を append せず署名**（server pub は検証鍵としてのみ）。iroh の #11（responder ML-DSA pub を署名被覆に含める）相当が TCP に無い → **A-resp を TCP でやるには server 署名の被覆拡張が要る**公算大。
- **node_id 欠如の channel binding 影響**: iroh は #2(nodeid_B) で transport channel を identity に束縛。TCP は raw socket でこれが無い → 「どの socket が どの identity か」の束縛が iroh QUIC より弱く、#7 指紋 pre-commit だけで TCP の MITM モデルに十分かを別途詰める（cross-transport replay を ctx 分離で塞いだ話とは別レイヤーの、TCP 単体 channel binding の問題）。
- ctx は既に transport-split（`nkct-handshake-tcp-v1`）で分離設計済み。TCP がまだ ctx 未配線なら現状維持（`ctx=""`）で放置してよく、増分3b で **tcp ctx 配線＋被覆修正＋#5flags/#7 マッピング**を一括投入する（iroh 先行で TCP に新たな穴は生じない）。

---

## 5. keybind 署名（§3.2）
```
keybind_blob =
    LP(mldsa_pk_owner_raw) ‖ u8(key_usage) ‖ LP(target_pubkey_raw) ‖
    LP(handle_utf8) ‖ u64_be(created_at) ‖ u8(has_expiry) ‖ [u64_be(expires_at) if has_expiry]
keybind_sig = ML-DSA-Sign(sk_owner, msg=keybind_blob, ctx=b"nkct-keybind-v1")
```
key_usage: `0x01=enc(ML-KEM)` / `0x02=hybrid(P-256)`。canonical=raw。

## 6. KeyBundle（§3.3）
```
KeyBundle =
    MAGIC(b"NKCB") ‖ u8(version=1) ‖
    LP(mldsa_pk_owner_raw) ‖ LP(handle_utf8) ‖ u64_be(created_at) ‖
    u16_le(n) ‖
      [ per i: u8(key_usage) ‖ LP(target_pubkey_raw) ‖ u64_be(created_at_i)
               ‖ u8(has_exp) ‖ [u64_be(exp_i)] ‖ LP(keybind_sig_i) ] * n ‖
    LP(self_sig)
self_sig = ML-DSA-Sign(sk_owner, msg=(MAGIC..最終 bound key, self_sig 除く全バイト), ctx=b"nkct-bundle-v1")
```
検証:
1. `fingerprint(mldsa_pk_owner) == ピン(known_peers)`。
2. `self_sig` を owner pk で検証(ctx=bundle)。
3. 各 `keybind_sig_i` を §5 blob 再構築して検証(ctx=keybind)。

### 6.1 非対話パス（§4.2）
`--recipient-pubkey` はライブ署名なし → §5 keybind + §6 self_sig で閉じる。受信者暗号鍵は bundle 検証で transitive 認証。配送手段不問。

### 6.2 【不変条件】署名再構築の網羅性
**検証後にコードが信頼する全フィールドが署名再構築対象に入っていること。** keybind_blob 再構築時:
- `mldsa_pk_owner` は **pin 済みの値**を使う（bundle 内平文を鵜呑みにしない）。
- `handle` は bundle レベル値を使う。
- `created_at_i / has_exp / exp_i / key_usage / target_pubkey` は blob に含まれるので再構築対象＝改竄は落ちる。
- **署名被覆外の平文を後段が1つでも信頼したら改竄経路になる。** 可能なら冗長平文を持たず単一ソースから再構築（重複削減）。

**(E) created_at の出所を固定**（取り違え防止）: keybind_blob 再構築時、`keybind_blob.created_at := entry.created_at_i`（bundle レベルの `created_at` ではない）、`handle := bundle レベル handle`、`owner := ピン済み値`。§5 の `created_at` と §6 エントリの `created_at_i` は別変数。

---

## 7. バージョニングと移行【FROZEN】
### (A) flag day
ctx 非空化はワイヤ破壊 → **ALPN version bump**。旧 peer は ALPN ネゴで clean fail。**ctx="" の旧検証パスを1本も残さず撤去**。WAN テストノード(OCI)・各デモ端末は同時更新前提。
### (B) 【撤回】allowlist ハードカットオーバーは不要になった
凍結時は「指紋前置 `nkct-id-v1` により既存 allowlist(hash-only)が全照合不能 → 旧エントリ破棄＋電話再確認」を (ii) ハードカットオーバーとして計画していた。**§3.1 で前置を撤回した結果、指紋値は `SHA3-256(raw)` のまま不変 → 既存 allowlist エントリはそのまま有効**。この feature は指紋スキームを変えないので、**allowlist の破壊的移行は発生しない**。
- 増分2 は allowlist を無効化せず、**known_peers に検証状態（verified/unverified）を additive に足すスキーマ進化＋指紋 wordlist 表示**に縮小する（非破壊）。既存 hash-only エントリは従来どおり trusted。
- 「旧 hash-only を trusted fallback にしない」という元の不変条件は、**指紋スキーム変更を前提にした移行時限定**の話であり、変更が消えた以上 moot。
- **要確認(運用) は解消**: 既存 allowlist 件数規模の確認は、移行自体が不要になったため不問。
- **(A) flag day は別問題として残る**: ハンドシェイク署名の ctx 非空化（増分3/7）はワイヤ破壊なので ALPN bump は依然必要。これは指紋とは無関係で、今回の撤回に影響されない。

---

## 8. テスト要件【KAT=deterministic / interop=verify-cross を分離】
**重要**: ML-DSA 署名は既定 randomized(hedged)＝**バックエンド間でバイト一致しない**。
- **KAT ゴールデン**: 指紋 / keybind_blob / handshake transcript / bundle の**バイト列**を pin。**署名バイトの KAT は deterministic 変種(固定 rnd)で** pin する（randomized のバイト比較で無用に落とさない）。
- **interop**: 「同一 (M, ctx, pk) の片側署名がもう片側で **verify** できる」ことで確認（OpenSSL↔RustCrypto、既存 14-case 準拠）。バイト比較ではない。
- 正準化一致: raw/SPKI 取り違えで指紋・pre-commit 比較が変わらない（指紋 = `SHA3-256(raw)`、前置なし＝§3.1）。指紋値が既存実装から不変であること（＝ allowlist/ticket/peer_id 互換）も KAT で固定。
- transplant: bundle A の keybind_sig を B に貼る → owner 自己言及不一致で落ちる。
- 被覆漏れ: transcript / keybind_blob / bundle の各フィールド改竄 → 検証が落ちる。
- **pre-commit すり替え(responder 側)**: initiator #7 を別 identity に → responder §4.2(A-resp) で abort。
- **【A の欠落補完】responder identity 置換(initiator 側)**: MITM が #11=M・sk_M で sig_R 署名 → **initiator が §4.2(A-init) で abort**（`fingerprint(#11)≠pin` かつピン検証で不成立）。含める側と検証する側の両方に abort テストを置く。
- **【C】pure ML-DSA(0x00) 固定**: interop verify-cross で「OpenSSL の context-string 経路が **pure ML-DSA(先頭 0x00)** で、pre-hash(0x01)に化けていない」を assertion 名 `mldsa_pure_ctx_both_backends` 等で明示。将来 OpenSSL 既定変更時に何が壊れたか即判別。
- **【cross-transport replay】**: iroh handshake(ctx=`nkct-handshake-iroh-v1`)で採取した sig を TCP handshake の検証(ctx=`nkct-handshake-tcp-v1`)に差す → ctx 差で verify 落ち。逆方向も。同一 transcript/鍵でも transport をまたいだ使い回しが不能なことを固定。
- **【D】エフェメラル鮮度**: 「2回のハンドシェイクが**異なる transcript と異なる導出鍵**を生む」。P-256/ML-KEM エフェメラルを cache/永続する経路が無いこと（鍵生成が握手毎に走る）。
- **auth モード各組合せ**: §4.3 通りに #5/#6/#7/#10/#11 の presence と cross-bind 挙動が一致。
- **presence フラグ**: #5 の reserved ビット非0 → 拒否。#5.bit1 有りで #7 欠落 → abort。
- **ピン無し refuse**: trust モード(#5.bit1)で pin 無し → 接続拒否。
- **downgrade**: #5.bit1 有りで responder 署名不在/不一致 → abort（§4.3）。
- identity 変更: known_peers ピン不一致 → 警告/停止。

---

## 9. 残確認
- **allowlist 運用件数(Q2)**: §3.1 前置撤回により allowlist の破壊的移行自体が不要になったため **moot**（既存エントリ有効）。増分2 は非破壊の known_peers スキーマ進化＋wordlist 表示（§7(B)）。
- 上記以外の §3–§6 バイトは凍結。フェーズ3(実装)着手可。

---

## 10. 実装不変条件（バイト非変更・検証ロジック/テストに畳み込む）

### (A) 検証鍵の pin 鎖 — §4.2 参照
initiator は sig_R を **ピン済み指紋に鎖して**検証（`fingerprint(#11)==pin` を MUST）。#7 pre-commit と**同一コミット**で実装（片肺禁止）。

### (B) パーサ堅牢化【本プロジェクトは peer ID 抽出で remote-triggerable panic の前科あり】
attacker-controlled な LP フィールドが handshake(#1–12)・keybind_blob・KeyBundle で大量に増える。**全 LP 解析を境界チェック必須・panic 禁止・明示 Result 化**:
- LP length > 残バッファ → reject。
- KeyBundle の `n` == 実パース数の一致検査。self_sig 後の trailing byte → reject。
- **固定長暗号オブジェクトは LP 長 == 定数を assert**（length-confusion 防御）: ML-DSA-65 pub=1952 / sig=3309 / ML-KEM-768 ek=1184。
  - **P-256 pub = 91B（SubjectPublicKeyInfo DER、増分3 で実測）**。raw SEC1 point の 65B ではない ── 本初版の "P-256=65" は raw 前提の誤りで、実装（`to_public_key_der` / SPKI）は DER で送る。65 で assert すると全ハンドシェイクが落ちる。定数はヘルパ（`backend::mldsa_pub_len`/`mldsa_sig_len`/`mlkem_ek_len`/`mlkem_ct_len`/`P256_SPKI_DER_LEN`）を単一ソースにし、doc の数値を手写ししない。
  - **#12 responder 静的 ML-KEM ek は optional**: responder が静的 KEM 鍵を publish しない時は empty（エフェメラル #9 が FS を担う正当状態）。よって #12 の長さ検査は**非 empty 時のみ**（empty=スキップ / 固定長=通過 / 中間長=Err の三分岐）。enc pin(target_enc_fp)設定時は SHA3(empty)≠fp で empty が別途弾かれるので、この例外は enc pin の安全性を緩めない。
  - 実装は Result 返し（`ensure_field_len`）で **`assert!` マクロ不使用**（attacker-controlled 長で panic すると remote DoS）。
- handshake パーサと bundle パーサに **fuzz target を1本ずつ**。
- 各 wire フォーマット実装と**同時に**堅牢化（後付けにしない）。

### (C) FIPS 204 pure(0x00) 経路の固定 — §2/§8 参照
`M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M` の先頭 0x00 は **pure ML-DSA**（0x01=HashML-DSA は別物）。OpenSSL の `context-string` param 経路が pure であることを interop verify-cross で固定。

### (D) エフェメラル鮮度
明示 nonce が無く、リプレイ/KCI 耐性は **P-256/ML-KEM エフェメラルが毎握手 fresh-random・非再利用・非永続**に全面依存。鍵生成が握手毎に走ることを実装不変条件＋コードレビュー観点＋§8 テストで担保。エフェメラル cache/永続経路 0 本。

### 実装順序（順序に織り込む2点）
1. **A（initiator 側ピン検証）は #7 pre-commit と同一コミット**（照合の対を一緒に）。
2. **B（パーサ堅牢化）は各 wire フォーマット実装と同時**（後付け禁止）。
KAT/negative の最後で A の「responder identity 置換 → initiator abort」を必ず追加。
dual-model レビューの重点 = A の両側 abort ／ B の fuzz ／ **cross-transport replay(iroh sig を TCP に差す negative)** の3点。

---

## 11. 署名文脈のスコープとドメイン分離（全 identity-鍵文脈）

同一 ML-DSA identity 鍵が署名する文脈（`pqc_sign` 全呼出し棚卸し）:

| 文脈 | 鍵 | 本feature後の分離 |
|---|---|---|
| iroh handshake (`p2p/processor`) | identity | native ctx `nkct-handshake-iroh-v1` |
| TCP handshake (`network/tcp`) | identity（同一 transcript） | native ctx `nkct-handshake-tcp-v1` |
| prekey (`prekey.rs`, PQFS) | identity | **byte-prefix → native ctx `nkct-prekey-v1` に統一**（増分4） |
| **recipient bundle (`one_shot.rs`)** | identity | **byte-prefix → native ctx `nkct-recipient-bundle-v1` に統一**（増分4） |
| keybind / bundle（新規） | identity | native ctx `nkct-keybind-v1` / `nkct-bundle-v1` |
| **file 署名 (`strategy/pqc`)** | identity | **ctx="" のまま据え置き（follow-up）** |
| MLS transport binding (`group/binding`) | **別鍵**（standalone transport、identity と独立）＋既存 domain-sep | **対象外（別鍵ゆえ相互 replay 不能）** |

> **【棚卸し訂正（増分4）】** 初版は「5つ」と数えていたが、`one_shot.rs` の **recipient bundle 署名（`nkct-recipient-bundle-v1`、identity 鍵で dsa_pub＋static_pk＋node_id＋inbox_ticket を署名、async/inbox 経路）を取りこぼしていた**。これも prekey と同型の byte-prefix＋ctx="" で、同じ file→X cross-replay を持つため、増分4 で prekey と同時に native ctx へ移行。§11.2 の「ctx="" に残るのは file 署名ただ1つ」の前提はこの追加で保たれる（recipient bundle が ctx="" のままだと孤立が崩れていた）。

### 11.1 prekey を native ctx に統一する理由と移行コスト
- §2 の「ctx と byte-prefix を混在させない」不変条件と、prekey だけ byte-prefix という現状は**自己矛盾**。混在は「文脈ごとに実装がばらけ分離漏れ＝replay 経路」（論点4）そのもの。
- **重要な訂正**: 「handshake が ctx を持てば handshake↔prekey は ctx 差で分離される」は**誤り**。機構が別レイヤー（prekey=M 本体前置、handshake=M' 前置）で、ctx が効くのは**両方が native ctx の時だけ**。よって prekey も native ctx に寄せる。
- **移行コスト = 軽**: prekey は **one-time**（消費で削除・高頻度 replenish、`prekey.rs`）。受信者が新スキーム(`nkct-prekey-v1`)で再 publish すれば、旧 byte-prefix 分は消費/失効で自然消滅。handshake ほどの移行負荷なし。→ **native ctx 化で確定**（独立 flag-day 1系統）。

### 11.2 file 署名を follow-up にする「正しい」論理
- file 署名を最後まで ctx 化しなくても、**他の identity-鍵文脈（handshake iroh/tcp・prekey・keybind・bundle）が全て native ctx に移れば、ctx="" に残るのは file 署名ただ1つ**になる。
- **孤立した ctx="" 文脈は、他の全 native-ctx 文脈と ctx 差で自動的に replay 不能**。これが (a) スコープを正当化する本当の論理（doc 前版の「prekey は ctx 差で分離」の誤記をこれに置換）。
- したがって file 署名の据え置きは「低リスクだから」ではなく「**他が全部 native ctx になれば ctx="" 孤立で分離が成立するから**」。file 署名自身の domain-sep は望ましいが別ハードニングとして follow-up。

### 11.3 MLS binding
別鍵（standalone transport ML-DSA）かつ既存で domain-separated。identity 鍵と共有しないため相互 replay の対象外。本feature では触らない。
