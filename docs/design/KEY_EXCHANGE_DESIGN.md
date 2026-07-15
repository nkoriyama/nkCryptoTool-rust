# 公開鍵授受 (ML-DSA 単一アンカー) — バイトフォーマット仕様

ML-DSA-65 を**単一の信頼アンカー**とする公開鍵授受。受信者の指紋を電話等 out-of-band で
確認し、その 1 つの identity 鍵が他の全鍵（暗号鍵・エフェメラル・binding）を署名で保証する。
transport は iroh のみ。TOFU（未検証初回接続の信頼）は持たない。

対話パス（live handshake）と非対話パス（KeyBundle / prekey inbox）の 2 つを、同一の指紋
アンカーの下に統一する。

---

## 1. エンコード規約
- **LP**: `u32 little-endian 長さ ‖ bytes`（可変長 pubkey / ct / sig）。
- **raw**: 固定長・前置なし。NodeId=32B、flags=1B、指紋=32B。
- **u64_be**(unix 秒) / **u16_le**(count)。
- **canonical pubkey = raw アルゴリズムバイト**。署名対象・hash 入力・pre-commit 比較の全てで
  raw を使う。SPKI DER は署名/hash 対象に入れない。

固定長（length-confusion 防御・§9(B) で assert）:
| オブジェクト | 長さ |
|---|---|
| ML-DSA-65 pub | 1952 B |
| ML-DSA-65 sig | 3309 B |
| ML-KEM-768 ek | 1184 B |
| P-256 pub | 91 B（SubjectPublicKeyInfo DER。raw SEC1 の 65B ではない） |

定数はバックエンドのヘルパ（`backend::mldsa_pub_len` / `mldsa_sig_len` / `mlkem_ek_len` /
`mlkem_ct_len` / `P256_SPKI_DER_LEN`）を単一ソースにする。

---

## 2. ドメイン分離ラベル（native ML-DSA ctx）

署名のドメイン分離は **ML-DSA (FIPS 204) の native context string** で行う（手動 byte-prefix は
使わない）。FIPS 204 は内部で `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M`（先頭 `0x00` = pure ML-DSA）と
符号化する。`pqc_sign(algo, sk, msg, ctx)` / `pqc_verify(algo, pk, msg, sig, ctx)` が `ctx: &[u8]`
を取り、rustcrypto は `try_sign(msg, ctx)`、openssl は `context-string` OSSL_PARAM に配線する。

### ラベル割当
同一 identity 鍵が署名する全文脈を prefix-free に分離する:

| 文脈 | ラベル |
|---|---|
| iroh handshake 署名 | `nkct-handshake-iroh-v1` |
| prekey 署名 (PQFS) | `nkct-prekey-v1` |
| recipient bundle 署名 (`one_shot.rs`, inbox/async) | `nkct-recipient-bundle-v1` |
| keybind 署名 | `nkct-keybind-v1` |
| KeyBundle self_sig | `nkct-bundle-v1` |
| **file 署名** (`strategy/pqc`) | **ctx=""**（唯一の空 ctx。§10 で孤立分離） |

指紋は署名 ctx ではなく識別子 hash（`SHA3-256(raw)`、前置なし）であり、この表の対象外（§3）。

**不変条件**: identity 鍵で ctx="" 署名する文脈は **file 署名ただ 1 つ**。他は全て native ctx。
新しい署名文脈を足すときは必ず native ctx で入れる（ctx="" を増やすと file の孤立分離が崩れる）。

---

## 3. 指紋
```
fingerprint = SHA3-256( mldsa_pk_owner_raw )      // 32 bytes, full, 前置なし
```
- 切り詰め禁止（full 256-bit、下限 128-bit）。canonical = raw（wire も raw、pin 比較で SPKI→raw）。
- 電話読み上げ: PGP wordlist（偶数/奇数交互、32B→32 語）＋チェックワード 1 語。指紋と KeyBundle
  表示で同一 wordlist。
- **統一識別子**: pin == routing peer_id == MLS binding fp == group id == ticket の pqc_sign_fp は
  全て同一値 `SHA3-256(dsa_pub_raw)`。この統一は load-bearing（割ると新規 misbinding 面が開く）。

---

## 4. ハンドシェイク署名（iroh）

両側が署名し相互検証する。`#5` / `#10` の flags バイトが後続フィールドの presence を
ワイヤ決定的に決める。

- **#5 = initiator flags (raw1)**: `bit0(0x01)=initiator_self_auth`→#6 支配、
  `bit1(0x02)=expects_responder_auth`→#7 支配。他ビットは reserved（=0、検証で拒否）。
- **#10 = responder flags (raw1)**: `bit0=responder_self_auth`→#11/#12 支配。他 reserved。

flags は署名対象内・支配するフィールドより前に置く → responder は #5 を先読みして #6/#7 の
パスを決定的に決める。

### 4.1 transcript

**initiator 署名対象（#1–#7）:**
| # | フィールド | enc | 条件 |
|---|---|---|---|
| 1 | nodeid_A (initiator) | raw32 | 常時 |
| 2 | nodeid_B (responder) | raw32 | 常時 |
| 3 | initiator P-256 eph | LP | 常時 |
| 4 | initiator ML-KEM pub | LP | 常時 |
| 5 | **initiator flags** | raw1 | 常時（bit0→#6, bit1→#7） |
| 6 | initiator ML-DSA pub | LP | #5.bit0 |
| 7 | **expected responder fingerprint** | **raw32** | **#5.bit1** |

`#7 = SHA3-256(mldsa_pk_responder_raw)`（§3 の素の指紋）。full pub でなく指紋にするのは、initiator
が ticket 経路では responder の指紋しか持たない（full pub を持つのは `--signing-pubkey` 時だけ）
ため。指紋なら全モードで #7 を構築でき、A-resp が全モードで成立する。
- **不変条件(a)**: initiator が pin から取り出す #7 と、responder が `SHA3-256(own_pub_raw)` で作る
  値が **同一の hash 定義**（前置なし、canonical=raw）で一致すること。
- **不変条件(b)**: responder は受信 #7 を信頼の入力にせず、自ら再導出した値を **比較する標的**と
  して扱う。

```
sig_I = ML-DSA-Sign(sk_I, msg=transcript[#1..#7], ctx="nkct-handshake-iroh-v1")
```

**responder 署名対象（#1–#12、同一 builder の続き）:**
| # | フィールド | enc | 条件 |
|---|---|---|---|
| 8 | responder P-256 eph | LP | 常時 |
| 9 | ML-KEM ct | LP | 常時 |
| 10 | **responder flags** | raw1 | 常時（bit0→#11/#12） |
| 11 | responder ML-DSA pub | LP | #10.bit0 |
| 12 | responder 静的 ML-KEM pub | LP | #10.bit0（optional。§9(B)） |

```
sig_R = ML-DSA-Sign(sk_R, msg=transcript[#1..#12], ctx="nkct-handshake-iroh-v1")
salt  = SHA3-256(transcript[#1..#12]) → HKDF
```

### 4.2 双方向 cross-check
含める側（pre-commit）と検証する側（pin 照合）の**両方**が要る。片方が欠けると misbinding が
裏口から復活する。

**(A-resp) responder 側** — initiator 署名（#1–#7）検証後:
```
if #5.bit1 (expects_responder_auth):
    assert #10.bit0 == 1                         // responder が実際に自己署名する
    assert #7 == SHA3-256(own_mldsa_pk_raw)      // 自ら再導出した指紋を #7 と照合
    不一致/不在 → abort（identity-misbinding / downgrade）
```

**(A-init) initiator 側** — responder 署名 sig_R は **ピン済み identity に鎖して**検証する。
wire の #11 をそのまま信頼して検証してはならない:
```
if #5.bit1 (expects_responder_auth):
    // pin 照合は sig 検証より前。全 identity 入力経路で保証:
    if target_sign_fp あり:   assert SHA3-256(#11) == target_sign_fp
    if signing_pubkey あり:   assert #11 == pinned_raw_pub
    verify(sig_R, msg=transcript[#1..#12], pk=#11, ctx=handshake) が成功
    いずれか不成立 → abort
```
攻撃: MITM が #11=M_pub・sk_M で sig_R を作り responder になりすます。wire の #11 で検証すると
通過し initiator が M を pin 済み P と誤信する。塞ぎ: pin 照合を sig 検証の**前**に MUST で強制
（#11 は冗長フィールド）。node_id(#2) と ML-DSA identity(#7/#11) の両方を束縛する。

### 4.3 auth モードマトリクス
trust / anonymous は呼び出し側の**明示選択**（pin 有無から暗黙推論しない）:

| #5.b0 | #5.b1 | #10.b0 | 挙動 |
|---|---|---|---|
| 1 | 1 | 1 | 相互認証。#7 pre-commit → §4.2 照合 |
| 0 | 1 | 1 | initiator anonymous・responder 認証。#7 pre-commit + §4.2 照合は残す |
| 1 | 0 | 0/1 | responder 認証せず。#7 無し |
| 0 | 0 | 0 | 完全 anonymous・信頼確立せず |

downgrade 検出: initiator が responder 認証を要求（#5.bit1）した場合、pin に鎖する有効な
responder 署名が来ない/一致しないことで abort する。

### 4.4 ピン無し接続を塞ぐ
- responder を認証するモード（#5.bit1）で target identity の pin が無い場合は**接続拒否**。
  #7 を空/欠落のまま握手を続行しない。
- 「pin 無し → 黙って anonymous に落ちる」を禁止（pin 不在自体を downgrade ベクタにしない）。

---

## 5. keybind 署名
```
keybind_blob =
    LP(mldsa_pk_owner_raw) ‖ u8(key_usage) ‖ LP(target_pubkey_raw) ‖
    LP(handle_utf8) ‖ u64_be(created_at) ‖ u8(has_expiry) ‖ [u64_be(expires_at) if has_expiry]
keybind_sig = ML-DSA-Sign(sk_owner, msg=keybind_blob, ctx="nkct-keybind-v1")
```
`key_usage`: `0x01=enc(ML-KEM)` / `0x02=hybrid(P-256)`。canonical=raw。`owner_pk` を自己言及的に
含める（anti-transplant: ある owner の keybind を別 owner の bundle に貼れない）。

---

## 6. KeyBundle
非対話配布の enc/hybrid 鍵束。1 つの ML-DSA identity（owner）の下に複数の暗号公開鍵を束ね、
self-signature で封をする。受信者暗号鍵はライブ署名を持たない（署名できる KEM/DH 鍵でない）ため、
keybind + self_sig で閉じ、bundle 検証で transitive に認証する。配送手段不問。

```
KeyBundle =
    MAGIC("NKKB") ‖ u8(version=1) ‖
    LP(mldsa_pk_owner_raw) ‖ LP(handle_utf8) ‖ u64_be(created_at) ‖
    u16_le(n) ‖
      [ per i: u8(key_usage) ‖ LP(target_pubkey_raw) ‖ u64_be(created_at_i)
               ‖ u8(has_exp) ‖ [u64_be(exp_i)] ‖ LP(keybind_sig_i) ] * n ‖
    LP(self_sig)
self_sig = ML-DSA-Sign(sk_owner, msg=(MAGIC..最終 bound key、self_sig 除く全バイト), ctx="nkct-bundle-v1")
```
magic `NKKB` は既存全 magic と相異。inbox/async 経路の recipient bundle（`one_shot.rs`, magic
`NKB1`, dsa_pub+static_pk+node_id+inbox_ticket）とは用途もフォーマットも別物。

**検証**:
1. `SHA3-256(mldsa_pk_owner) == 指紋 pin`。
2. `self_sig` を owner pk で検証（ctx=bundle）。
3. 各 `keybind_sig_i` を §5 blob 再構築して検証（ctx=keybind）。

**署名再構築の網羅性（不変条件）**: 検証後にコードが信頼する全フィールドが署名再構築対象に
入っていること。keybind_blob 再構築時、`owner` = **pin 済みの値**（bundle 内平文を鵜呑みにしない）、
`handle` = bundle レベル値、`created_at` = **エントリの `created_at_i`**（bundle レベルの `created_at`
ではない）。署名被覆外の平文を後段が 1 つでも信頼したら改竄経路になる。

**expiry**: 検証は真正性のみ（`expires_at` が改竄されていないこと）を保証し、時刻判定はしない
（reproducible / KAT-testable）。期限切れの拒否は caller が現在時刻と照合して行う。

**CLI**: 送信者は `--recipient-keybundle <NKKB> --recipient-fingerprint <64hex>` で消費（指紋 pin ＋
検証 ＋ 使用鍵の expiry 入口強制）。受信者暗号鍵はメモリ注入し公開鍵をディスクに書かない。raw
公開鍵の直接入力（`--recipient-pubkey` 等）は廃止（未認証鍵材料ゆえ）。owner は `--gen-keybundle`
で自分の暗号公開鍵を束ねて署名し、指紋を印字（out-of-band 共有用）。

---

## 7. バージョニングと移行
handshake 署名の ctx 非空化はワイヤ破壊なので、handshake を走らせる全 ALPN を version bump し、
ctx="" の旧検証パスは 1 本も残さない（旧 peer は ALPN ネゴで clean fail）。

| ALPN | 版 | 備考 |
|---|---|---|
| chat / file / shell / fwd / scp | `chat/2` `file/3` `shell/2` `fwd/2` `scp/2` | mutual-auth handshake を走らせる |
| mls / inbox | `mls/1` `inbox/1` | この handshake を走らせない別サブシステム → 非対象 |

指紋は `SHA3-256(raw)` のまま不変なので、既存 allowlist / ticket / inbox peer_id / MLS binding /
group id は全て有効。指紋スキームは変えないため allowlist の破壊的移行は発生しない。known_peers は
検証状態（verified / unverified）を additive に持つ。

prekey / recipient-bundle の native ctx 化は独立系統。prekey は one-time（消費/失効で自然消滅）
なので移行負荷は軽い。

---

## 8. テスト要件
ML-DSA 署名は既定 randomized（hedged）＝バックエンド間でバイト一致しない。KAT（決定的バイト固定）
と interop（cross-verify）を分離する:

- **KAT ゴールデン**: 指紋 / keybind_blob / handshake transcript / KeyBundle body の**署名前
  決定的バイト**を pin。指紋値が既存実装から不変（= allowlist/ticket/peer_id 互換）を固定。
- **interop**: 同一 `(M, ctx, pk)` の片側署名がもう片側で **verify** できることで確認
  （OpenSSL ↔ RustCrypto）。バイト比較ではない。
- **pure ML-DSA(0x00) 固定**: ctx が FIPS-204 純ドメイン（先頭 0x00）であり pre-hash(0x01) や
  message 連結でないことを assert（将来のバックエンド既定変更を検知）。
- **cross-context replay**: handshake で採取した sig を別文脈の検証（prekey / recipient-bundle /
  file ctx=""）に差す → ctx 差で verify 落ち。逆も。
- **transplant**: bundle A の keybind_sig を B に貼る → owner 自己言及不一致で落ちる。
- **field-tamper**: transcript / keybind_blob / bundle の各フィールド改竄 → 検証が落ちる。
- **A-resp / A-init abort**: initiator #7 を別 identity に → responder abort。MITM が #11=M で
  sig_R → initiator abort（`fingerprint(#11)≠pin`）。両側に abort テストを置く。
- **presence / auth モード**: #5 reserved ビット非0 → 拒否。#5.bit1 有りで #7 欠落 → abort。
  #12 三分岐（empty=skip / 固定長=通過 / 中間長=Err）。各 auth モードの presence が §4.3 通り。
- **ピン無し refuse**: trust モードで pin 無し → 接続拒否。
- **エフェメラル鮮度**: 2 回の握手が異なる transcript と導出鍵を生む（cache/永続経路なし）。
- **パーサ fuzz**: handshake パーサと KeyBundle パーサに fuzz（malformed 入力で panic せず Err）。

---

## 9. 実装不変条件

### (A) 検証鍵の pin 鎖
initiator は sig_R を **ピン済み指紋に鎖して**検証（`fingerprint(#11)==pin` を MUST、sig 検証の前）。
§4.2 参照。

### (B) パーサ堅牢化
attacker-controlled な LP フィールドが handshake(#1–12) / keybind_blob / KeyBundle に多数ある。
全 LP 解析を境界チェックし、**panic 禁止・明示 Result 化**（`assert!` マクロ不使用 — attacker-
controlled 長で panic すると remote DoS）:
- LP length > 残バッファ → reject。
- KeyBundle の `n` == 実パース数の一致検査。self_sig 後の trailing byte → reject。
- 固定長暗号オブジェクトは LP 長 == 定数を assert（§1 の長さ表）。
- **#12 responder 静的 ML-KEM ek は optional**: publish しない時は empty（エフェメラル #9 が FS を
  担う正当状態）。長さ検査は非 empty 時のみ（empty=スキップ / 固定長=通過 / 中間長=Err）。

### (C) FIPS 204 pure(0x00) 経路
`M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M` の先頭 0x00 は pure ML-DSA（0x01=HashML-DSA は別物）。両バック
エンドが pure であることを interop verify-cross で固定。

### (D) エフェメラル鮮度
明示 nonce が無く、リプレイ/KCI 耐性は P-256/ML-KEM エフェメラルが**毎握手 fresh-random・
非再利用・非永続**であることに全面依存。鍵生成が握手毎に走り、cache/永続経路は 0 本。

---

## 10. 署名文脈のスコープ
同一 ML-DSA identity 鍵が署名する全文脈と、そのドメイン分離:

| 文脈 | 鍵 | ctx |
|---|---|---|
| iroh handshake (`p2p/processor`) | identity | `nkct-handshake-iroh-v1` |
| prekey (`prekey.rs`, PQFS) | identity | `nkct-prekey-v1` |
| recipient bundle (`one_shot.rs`) | identity | `nkct-recipient-bundle-v1` |
| keybind (`keybundle.rs`) | identity | `nkct-keybind-v1` |
| KeyBundle self_sig (`keybundle.rs`) | identity | `nkct-bundle-v1` |
| file 署名 (`strategy/pqc`) | identity | **ctx=""** |
| MLS transport binding (`group/binding`) | **別鍵** | 対象外 |

**file 署名の孤立分離**: identity 鍵で ctx="" 署名するのは file 署名ただ 1 つ。孤立した ctx=""
文脈は、他の全 native-ctx 文脈と ctx 差で自動的に replay 不能（file↔handshake / prekey / bundle は
ctx 差で verify 落ち）。file 署名自身のドメイン分離は望ましいが別ハードニング。

**MLS binding は対象外**: standalone transport の別 ML-DSA 鍵で署名し、identity 鍵と共有しない
ため相互 replay の対象にならない。
