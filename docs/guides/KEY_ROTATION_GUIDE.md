# ローカルファイル暗号化のための長期 KEM 鍵ローテーション運用ガイド

> 本書は [PQFS_DESIGN.md](../design/PQFS_DESIGN.md) フェーズ 3（§5.3 / des5）の成果物である。
> 対象は **ローカルファイルの自己暗号化** (`--mode pqc|hybrid --encrypt`) に限る。
> inbox 非同期配送経路は One-Time Prekey で PQ-FS を達成済みのため本書の対象外
> （[PQFS_DESIGN.md §3.2](../design/PQFS_DESIGN.md) 参照）。ライブ P2P も達成済み。

---

## 1. なぜ鍵ローテーションが必要か

ローカルファイル暗号化では、暗号化時に受信者（ephemeral 性を提供する主体）が存在しない。
送信者は受信者の **長期固定公開鍵のみ** を使って封緘するため、生成された暗号文は
受信者の **長期秘密鍵のみで復号可能** である（[PQFS_DESIGN.md §3.1](../design/PQFS_DESIGN.md)）。

このため Prekey 方式（=対話相手が ephemeral 鍵を出すことに依存）は原理的に使えず、
**完全な Forward Secrecy は技術的に保証できない**。唯一の緩和策が

> 長期 KEM 鍵を高頻度でローテーションし、古い秘密鍵を確実に破棄（zeroize/shred）する

ことである（[PQFS_DESIGN.md §3.2 NOTE / §6-1](../design/PQFS_DESIGN.md)）。

### 想定する鍵漏洩シナリオ
1. **秘密鍵ファイルの流出**（バックアップ・盗難・マルウェア）。`--mode pqc`（ML-KEM）でも
   秘密鍵が漏れれば、その鍵宛の暗号文はすべて即座に復号される（量子計算機すら不要）。
2. **Harvest-Now-Decrypt-Later (HNDL)**: 攻撃者が暗号文を保存し、将来の鍵漏洩を待つ。
   `--mode hybrid` の **ECDH 古典成分** は将来の量子計算機で突破され得るため、ECDH 秘密鍵の
   漏洩を待たずとも、harvest した暗号文が後日復号される余地がある（ML-KEM 成分は量子耐性）。

---

## 2. ローテーションが達成すること／しないこと

ローテーションの本質は **1 つの鍵漏洩で露出するファイル集合（blast radius）を、その鍵の
有効期間中に封緘したファイルだけに限定する** ことである。

| | 効果 |
|---|---|
| ✅ 達成する | 鍵 $K_n$ の漏洩で露出するのは「$K_n$ 宛に封緘された暗号文」のみに限定される。旧鍵 $K_{n-1}$ を破棄済みなら、$K_{n-1}$ 宛の暗号文は $K_n$ 漏洩では露出しない。 |
| ✅ 達成する | 将来鍵を生成・破棄するたびに、過去の各世代の暴露ウィンドウが時間的に区切られる。 |
| ❌ 達成しない | **既に封緘済みの暗号文を遡って保護することはない。** 旧暗号文は旧鍵に束縛されたままで、旧秘密鍵が存在する限り復号可能。 |
| ❌ 達成しない | 鍵をローテーションするだけでは旧暗号文の暴露は減らない。**旧暗号文を新鍵へ再封緘し、かつ旧秘密鍵を破棄して初めて** その世代の暴露が消える。 |

### 核心となるトレードオフ
旧暗号文の暴露を実際に消すには、相反する 2 操作を **両方** 行う必要がある:

1. **旧暗号文を新鍵へ再封緘**（再暗号化）する — さもないと旧鍵を破棄するとアクセスを失う。
2. **旧秘密鍵を破棄**する — さもないと旧暗号文は旧鍵で復号可能なまま。

再封緘せずに旧鍵を破棄すれば「暴露は消えるがデータも読めなくなる」。
旧鍵を残したまま新鍵に切り替えれば「読めるが暴露も残る」。
**意味のあるローテーション = 再封緘 → 旧鍵破棄** をセットで実施することである。

---

## 3. ローテーション手順

以下は `--mode pqc`（ML-KEM-768）の例。`--mode hybrid` は鍵ファイルが
mlkem/ecdh の 2 対になる点だけ異なる（§5 参照）。

鍵世代は **世代ごとに別ディレクトリ** で管理し、鍵ファイルの上書き事故を避ける。
ディレクトリ名に日付を入れて世代を追跡可能にする。

```bash
# 0. 現行世代（破棄予定）
OLD=~/.nkkeys/2026-06     # public_enc_pqc.key / private_enc_pqc.key

# 1. 新世代の鍵ペアを生成（新ディレクトリへ）
NEW=~/.nkkeys/2026-09
nkct --mode pqc --gen-enc-key --key-dir "$NEW"
#   → $NEW/public_enc_pqc.key, $NEW/private_enc_pqc.key（0600）

# 2. 新しい暗号化鍵を束ねた署名済み KeyBundle を発行し、印字される指紋を
#    out-of-band で送信者に配布する（生公開鍵の直接配布は廃止）。
#    KeyBundle の identity は常に ML-DSA-65（$NEW に pqc の署名鍵がある前提）。
nkct --mode pqc --gen-keybundle --key-dir "$NEW" \
    --signing-privkey "$NEW/private_sign_pqc.key" \
    --keybundle-handle me --keybundle-output "$NEW/me.nkkb"
#   → "…fingerprint: <64-hex>" を控えて送信者に共有する
FP=<上で表示された 64-hex>

# 3. 旧鍵で封緘済みのファイルを新 KeyBundle へ再封緘（decrypt → encrypt）
#    一時平文はメモリ上ではなく必ずディスクに落ちる点に注意（§4 の破棄対象）。
for ct in archive/*.bin; do
    tmp=$(mktemp)
    nkct --mode pqc --decrypt \
        --user-privkey "$OLD/private_enc_pqc.key" --output-file "$tmp" "$ct"
    nkct --mode pqc --encrypt \
        --recipient-keybundle "$NEW/me.nkkb" --recipient-fingerprint "$FP" \
        --output-file "$ct.new" "$tmp"
    shred -u "$tmp"            # 一時平文を確実に破棄（§4 の caveat 参照）
    mv "$ct.new" "$ct"
done

# 4. 再封緘の成否を検証してから、旧秘密鍵を破棄（§4）
#    （検証前に旧鍵を消すとロールバック不能になる）
```

> [!IMPORTANT]
> 手順 3 と 4 の順序を守ること。**再封緘の完了と検証を確認してから旧秘密鍵を破棄** する。
> 逆順では、再封緘に失敗したファイルが復号不能（恒久的データ損失）になる。

### 3.1 鍵リング運用（my-identities）でのローテーション

鍵を `keyring.db` に置いている場合（USAGE §0.1/§2.1）も、**新世代はいったんファイルで
生成して再封緘し、検証後に keyring を入れ替える**。my-identities のスロット
（`me:enc:ML-KEM-768` 等）は**単一占有**（クロバー防御）なので、旧鍵が入ったまま
新鍵を同じスロットへ生成・取り込みはできない — これは identity の暗黙置換を防ぐ意図的な設計。

```bash
# 手順 1〜2 は従来どおりファイルで（$NEW に生成・KeyBundle 発行）。
# 手順 3 の復号側は keyring 自動マッチが使える（--user-privkey 省略可）。

# 4'. 再封緘の検証後、keyring のスロットを新世代に入れ替える
nkct --keyring-cmd remove-my-key --key-role enc --key-algo ML-KEM-768
nkct --keyring-cmd import-my-key \
    --user-privkey "$NEW/private_enc_pqc.key" --shred-original
#   （--shred-original で新世代のファイル原本も抹消 → 以後は keyring のみ）
```

- `remove-my-key` は DB からレコードを削除するが、redb のファイル自体に旧ページが
  残留し得る（§4 の媒体特性と同種の caveat）。恒久的な保護は「格納されている秘密鍵が
  常にパスフレーズ暗号化済みである」ことにある。
- 署名鍵（identity）のローテーションは指紋＝identity そのものが変わるため、この
  ガイドの範囲外（全ピアとの再ピン留め・再ペアリングが必要）。

---

## 4. 旧秘密鍵の安全な破棄

本ツールは **メモリ上** の秘密鍵を `Zeroizing` / `ZeroizeOnDrop` で消去するが、
**ディスク上** の秘密鍵ファイルの破棄は OS の責務である。再封緘・検証の完了後:

```bash
shred -u "$OLD/private_enc_pqc.key"     # ハイブリッドは mlkem/ecdh 両方
```

### 破棄時の注意（媒体特性）
- **SSD / NVMe**: ウェアレベリングと FTL のため `shred` の上書きが物理ブロックに届く保証はない。
  可能なら **暗号化ファイルシステム（LUKS 等）上に鍵を置き、鍵ごと破棄** する運用が確実。
- **tmpfs（RAM）**: このリポジトリの作業環境では `/tmp` が tmpfs（RAM）であり再起動で揮発する。
  一時平文（手順 3 の `$tmp`）を tmpfs 上に置けば物理残存リスクは下がるが、スワップに注意。
- **TPM 保護鍵（`--use-tpm`）**: 秘密鍵は TPM 封印された wrapped blob として保存される。
  破棄は **wrapped blob ファイルを削除** すれば足りる（TPM 外に平文秘密鍵は存在しない）。
  ※ TPM 保護鍵はネットワークリスナーモードでは未サポートだが、ローカル `--encrypt`/`--decrypt`
  では利用可能（[README](../../README.md) 参照）。

---

## 5. Hybrid モードの差分

`--mode hybrid` では暗号化鍵が ML-KEM と ECDH の **2 対** に分かれる
（`public_enc_hybrid_mlkem.key` / `public_enc_hybrid_ecdh.key` と各 private）。KeyBundle は
両方を 1 つの署名済み束に収める（送信側は `--recipient-keybundle` 1 本で足りる）。

```bash
# 生成 + KeyBundle 発行（両鍵を束ねる。identity は ML-DSA-65）
nkct --mode hybrid --gen-enc-key --key-dir "$NEW"
nkct --mode hybrid --gen-keybundle --key-dir "$NEW" \
    --signing-privkey "$NEW/private_sign_hybrid.key" \
    --keybundle-handle me --keybundle-output "$NEW/me.nkkb"    # → 指紋 $FP を控える

# 再封緘（decrypt → encrypt）
nkct --mode hybrid --decrypt \
    --user-mlkem-privkey "$OLD/private_enc_hybrid_mlkem.key" \
    --user-ecdh-privkey  "$OLD/private_enc_hybrid_ecdh.key" \
    --output-file "$tmp" "$ct"
nkct --mode hybrid --encrypt \
    --recipient-keybundle "$NEW/me.nkkb" --recipient-fingerprint "$FP" \
    --output-file "$ct.new" "$tmp"
```

破棄時は **mlkem・ecdh 両方** の private を shred する。HNDL の観点では特に
**ECDH 古典成分の旧秘密鍵を残さない** ことが重要（量子突破の標的になるため）。

---

## 6. 運用上の推奨

- **ローテーション頻度**: 暴露ウィンドウ＝ローテーション間隔。脅威に応じて決める。
  長期保管用途では四半期ごと程度、機微度が高い場合はより短く。**「鍵を分けたい単位」=
  「漏洩を独立させたい単位」** で世代を切る（用途・相手・期間ごとに別鍵も有効）。
- **世代管理**: `--key-dir` を世代別（日付入り）に分ける。鍵ファイル名は固定なので、
  同一ディレクトリでの再生成は **上書き事故** になる。
- **公開鍵の再配布**: ローテーションのたびに新公開鍵を送信者へ配布し、指紋を確認させる。
- **再封緘できないアーカイブ**: 第三者保管などで再封緘不能な旧暗号文がある場合、
  その世代の旧秘密鍵を破棄すると当該データは恒久的に失われる。**「再封緘して残す」か
  「諦めて破棄する」か** を世代単位で明示的に判断する。
- **検証の自動化**: 手順 3 の再封緘後、`--decrypt` で新暗号文が平文に戻ることを
  全件確認してから旧鍵を破棄する（CI/スクリプト化推奨）。

---

## 7. 限界（再掲）と他経路との関係

| 経路 | PQ-FS | 緩和 |
|---|---|---|
| ライブ P2P（対話） | ✅ 達成済み | 毎接続 ephemeral KEM（[PQFS_DESIGN.md §0](../design/PQFS_DESIGN.md)） |
| inbox 非同期配送 | ✅ 達成可能 | One-Time Prekey（[PQFS_DESIGN.md §3.2](../design/PQFS_DESIGN.md)） |
| **ローカルファイル自己暗号化** | ❌ 原理的に不可 | **本書の鍵ローテーション運用のみ** |

ローカルファイル経路は、相手不在ゆえ ephemeral 性の源泉が無く、完全 FS を
技術的に保証できない。本書の運用は FS の「代替」ではなく **暴露の時間的封じ込め** であり、
その有効性は **旧秘密鍵を確実に破棄できるか** に全面的に依存する。

### 補助コマンドについて
[PQFS_DESIGN.md §5.3](../design/PQFS_DESIGN.md) は「（任意の）補助コマンド」を挙げているが、
本フェーズの確定スコープは **運用ガイドの文書化**（本書）である。再封緘ループ（§3 手順 3）と
破棄（§4）は既存の `--encrypt`/`--decrypt` と OS の `shred` で完結するため、専用サブコマンドは
当面不要と判断する。将来「世代管理・一括再封緘・検証」を 1 コマンド化する価値が出た場合の
**機能候補** として残す。
