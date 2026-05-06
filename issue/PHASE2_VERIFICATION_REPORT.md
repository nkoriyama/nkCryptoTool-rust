# Phase 1 v3 + Phase 2 統合検証レポート (Iroh 移行) — nkCryptoTool-rust

作成日: 2026-05-06
対象:
- `PHASE1_REMEDIATION_REPORT_v3_COMPLETE.md` (Phase 1 残課題の最終修正主張)
- `PHASE2_COMPLETION_REPORT.md` (Phase 2 完了主張)
前提:
- `PHASE1_VERIFICATION_REPORT.md` (v1)
- `PHASE1_VERIFICATION_REPORT_v2.md` (v2)
- `PHASE1_VERIFICATION_REPORT_v3.md` (v3)
役割: 弱点抽出のみ (修正方針は別パーティ)

---

## エグゼクティブサマリ

**Phase 1 v3 で指摘した問題は全件修正確認** (F-IROH-22 / F-IROH-16 / F-IROH-19 / F-IROH-25 / F-IROH-12)、**Phase 2 の主要機能 (ticket 完全版 / MITM 検知 / QR / CLI エイリアス) も実装を確認**。一方で以下の Medium 級欠陥が新規または継続:

- **F-IROH-26**: `target_enc_fp` がデッドコード (ticket に enc_fp を載せるが照合経路がない)
- **F-IROH-27**: EndpointGuard の async cleanup が fire-and-forget で確実性に欠ける
- **F-IROH-28**: F-IROH-23 進化形 — multi-client 認証がプロトコル上不可能
- **F-IROH-29**: ticket 指紋生成が 6 段ネスト if-let で silent fail
- **F-IROH-30**: 全テストが `chat_mode=false` のため、Iroh 上の chat_loop は一度もテストされていない
- **F-IROH-31**: production の relay_mode が Default (公式 relay にメタデータ漏洩可)
- **F-IROH-32**: `--test-threads=1` 強制が build/CI で担保されていない

---

## 修正状況サマリ

| 指摘 | 修正主張 | 実コード |
|---|---|---|
| F-IROH-22 (偽 auth ログ) | ✅ 修正完了 | ✅ **完全修正** (line 256: pqc_verify 成功直後のみ出力) |
| F-IROH-16 (allowlist デッドコード) | ✅ 修正完了 | ✅ **完全修正** (line 277-279: `_` アームが無条件 reject) |
| F-IROH-19 (ticket 形式) | ✅ Phase 2 で完全実装 | ✅ **完全実装** (`src/ticket.rs`: nkct1 + Base32 + version + addrs + PQC fp + CRC32) |
| F-IROH-25 (Drop ガード) | ✅ EndpointGuard 導入 | ⚠️ **fire-and-forget な async cleanup** (F-IROH-27) |
| F-IROH-12 (負例テスト) | ✅ 5 件 PASS | ⚠️ **chat_loop 未テスト** (F-IROH-30) |
| F-IROH-02 (PQC 指紋 bundle) | ✅ Phase 2 で完了 | △ **target_enc_fp が未使用** (F-IROH-26) |
| MITM 検知 | ✅ Phase 2 で完了 | △ **sign_fp のみ、enc_fp は dead code** |
| QR コード表示 | ✅ Phase 2 で完了 | ✅ 実装確認 (line 147-153) |
| CLI エイリアス | ✅ Phase 2 で完了 | ✅ 実装確認 (`main.rs:53, 62`) |

---

## ✅ 修正確認の詳細

### F-IROH-22 完全修正
`src/network/iroh.rs:241-262`

```rust
if let Some(ref pubkey_path) = config.signing_pubkey {
    // ... pqc_verify ...
    peer_id_opt = Some(PeerId::Pubkey(hash));
    eprintln!("Client authenticated successfully."); // ← pqc_verify 成功内のみ
} else if !config.allow_unauth {
    return Err(...);
}
```

ログは pqc_verify 成功直後のブロック内のみ。`signing_pubkey=None + allow_unauth=true` で署名を読み捨てるパスでは出力されない。

### F-IROH-16 完全修正
`src/network/iroh.rs:270-281`

```rust
match peer_id {
    PeerId::Pubkey(hash) => {
        if !allowlist.contains(&hash) { return Err(...); }
    }
    _ => {
        return Err(...);  // ← 無条件 reject (デッドコード解消)
    }
}
```

allowlist 設定 + 匿名ピア = 即座 reject。`test_iroh_handshake_allowlist_reject` で機能確認。

### F-IROH-19 / F-IROH-02 ticket フォーマット
`src/ticket.rs` で `IROH_MIGRATION_PLAN.md` 仕様にほぼ準拠した実装:

- `nkct1` プレフィックス ✅
- BASE32_NOPAD ✅
- version (=1) ✅
- NodeId / relay_url / direct_addrs (IPv4/IPv6) / pqc_fp_algo / pqc_sign_fp / pqc_enc_fp ✅
- CRC32 (CRC_32_ISO_HDLC) ✅
- 短すぎる ticket / version 不一致 / checksum 不一致 を弾く ✅

### F-IROH-25 部分修正 (F-IROH-27 として再分類)
`src/network/iroh.rs:23-31`

EndpointGuard 構造体を導入し、`start()` / `run_connect()` / `listen_with_sender()` の各所で配置。Drop で `tokio::spawn` 経由の close を実行。

ただし async cleanup の確実性に課題あり (F-IROH-27 参照)。

### F-IROH-12 部分修正 (負例 3 件追加、ただし chat_loop 未テスト)
追加されたテスト:

| テストケース | 内容 |
|---|---|
| `test_iroh_handshake_unauth` | 未認証許可成功 |
| `test_iroh_handshake_auth_success` | 双方向 ML-DSA 認証成功 |
| `test_iroh_handshake_auth_fail_fingerprint_mismatch` | MITM (指紋不一致) 検知 |
| `test_iroh_handshake_auth_fail_invalid_sig` | 署名不正検知 |
| `test_iroh_handshake_allowlist_reject` | Allowlist による拒否 |

全 5 件 PASS と報告。ただし全て `chat_mode=false` のため、本番の chat_loop は未通過 (F-IROH-30)。

---

## 🟡 新規 Medium 問題

### F-IROH-26: `target_enc_fp` がデッドコード
`src/network/iroh.rs:391-396, 472-478`

```rust
// run_connect で ticket から fp 抽出
if ticket.pqc_fp_algo & 1 != 0 {
    config.target_sign_fp = Some(ticket.pqc_sign_fp);
}
if ticket.pqc_fp_algo & 2 != 0 {
    config.target_enc_fp = Some(ticket.pqc_enc_fp);  // ← 設定するが…
}

// MITM チェック
if let Some(expected_fp) = config.target_sign_fp {
    let actual_fp: [u8; 32] = Sha3_256::digest(&raw_pub).into();
    if actual_fp != expected_fp {
        return Err(...);  // sign_fp のみ照合
    }
}
// target_enc_fp の照合コードは存在しない
```

サーバ生成 ticket には ML-KEM 鍵指紋 (`enc_fp`) が含まれる (`start()` line 127-142) が、**ハンドシェイク中にサーバの KEM 公開鍵は送信されない** (server は `client_kem_pub` を使って encap するだけ) ため、検証対象が存在しない → `target_enc_fp` は **完全な dead code**。

ticket には enc_fp を載せているのに照合できない、という非対称性。意図不明 (Phase 3 のファイル転送向け予約か?)。文書化または削除が必要。

### F-IROH-27: EndpointGuard の async cleanup は fire-and-forget
`src/network/iroh.rs:23-31`

```rust
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let endpoint = self.0.clone();
        tokio::spawn(async move {  // ← detached task
            endpoint.close().await;
        });
    }
}
```

問題:

1. **runtime 不在時に panic**: メイン関数終了後の Drop や、ランタイム停止後の Drop で `tokio::spawn` がパニック ("there is no reactor running")。
2. **detached task の完了保証なし**: spawn 後にプロセス終了すると close が完了しない可能性。`close().await` は relay session のクリーンクローズ通知を含むので、これが省かれると relay 側にゾンビセッションが残る。
3. **`server_task.abort()` との相互作用**: テストで `server_task.abort()` するとタスク内のローカル変数 (EndpointGuard 含む) が drop され spawn が起きるが、spawn 先のタスクは abort された task 木の外で実行される — これがテストハングを引き起こす余地。

ベストエフォートの cleanup としては機能するが、F-IROH-25 で言及した「Drop ガードによる確実な解放」とは厳密には一致しない。

### F-IROH-28: `signing_pubkey=None + allowlist + allow_unauth=true` で全接続拒否
`src/network/iroh.rs:241-281`

F-IROH-16 修正の副作用として、以下の構成は全クライアント拒否になる:

- 認証付き複数クライアント受け入れ (multi-client server) を意図して `signing_pubkey=None` (specific peer に固定したくない) + allowlist (PQC 指紋で許可リスト) + `allow_unauth=true` を設定
- → クライアントは署名を送るが、サーバは `signing_pubkey=None` で検証パスに入らず、peer_id は `PeerId::Node` のまま (line 264-266)
- → allowlist match の `_` アームで無条件 reject

根本原因: **プロトコル上、クライアントが DSA 公開鍵を送信しない**。サーバは事前に known な pubkey でしか署名検証できない。multi-client 認証の構造的不可能性。

これは F-IROH-23 の継続で、F-IROH-16 の正しい修正によって表面化。プロトコル拡張 (client が pubkey も送る) が必要。

### F-IROH-29: ticket 指紋生成の silent fail
`src/network/iroh.rs:110-142`

```rust
if let Some(ref path) = self.config.signing_privkey {
    if let Ok(bytes) = std::fs::read(path) {
        if let Ok(pem) = std::str::from_utf8(&bytes) {
            if let Ok(der) = crate::utils::unwrap_from_pem(pem, "PRIVATE KEY") {
                if let Ok(decrypted) = crate::utils::extract_raw_private_key(&der, ...) {
                    if let Ok(raw_priv) = crate::utils::unwrap_pqc_priv_from_pkcs8(...) {
                        if let Ok(raw_pub) = backend::pqc_pub_from_priv_dsa(...) {
                            sign_fp = Some(...);  // ← 全段成功時のみ
                        }
                    }
                }
            }
        }
    }
}
```

6 段ネストの `if let Ok` で全エラーを silent drop。問題:

- ファイル不在 / 読み込みエラー / passphrase 不一致 / 不正 PEM → 全て無言で `sign_fp = None`
- ユーザは ticket に PQC 指紋が含まれない理由を知らない
- MITM 検知が無効になっているが、ユーザは気付かない (致命的)

特に **passphrase 不一致** でこのパスが silent fail すると、運用上発見が困難。エラー昇格すべき。

### F-IROH-30: chat_mode=true テストが依然として 0 件
全 5 テストが `chat_mode=false` で `cfg!(test)` ショートカット (line 372-375, 534-536) を経由。**実際の `chat_loop` は Iroh トランスポート上で一度もテストされていない**:

- QUIC ストリーム上の framing
- nonce 検出 / replay 防御
- 暗号化/復号
- IDLE_TIMEOUT
- スレッド間の正しい abort

これらは TCP テストでは動いているが Iroh の `RecvStream` / `SendStream` で同等に動作する保証はない。回帰テストとしての価値が限定的。

### F-IROH-31: production の relay_mode が Default のまま
`src/network/iroh.rs:401`

```rust
.relay_mode(if cfg!(test) { iroh::RelayMode::Disabled } else { iroh::RelayMode::Default })
```

production では Iroh 公式 relay (Number Zero 運営) を使用可能な状態。Phase 3 で `--no-relay` を実装予定とのことだが、現状は **公式 relay へのメタデータ漏洩を許容** (どの NodeId 同士が通信したかを relay は観測可能)。

「高秘匿チャット」用途を志向するなら早めに対処が必要。

### F-IROH-32: `--test-threads=1` 強制が build/CI 設定で担保されていない
`PHASE1_REMEDIATION_REPORT.md` で「シングルスレッド固定」と書かれているが、コード上は単に `reset_state()` を各テスト先頭で呼んでいるだけ。並列実行されると `CHAT_ACTIVE` / `PEER_COOLDOWNS` のグローバル状態が交錯する。

`Cargo.toml` の `[[test]]` セクションや CI 設定で強制されない限り、開発者が普通に `cargo test` を叩くと壊れるテストになっている。`#[serial]` (serial_test クレート) を使うのが一般的な対処。

---

## 引き継ぎ (継続オープン)

| ID | 状態 |
|---|---|
| F-IROH-03 | ALPN ハードコード — 未対応 |
| F-IROH-08 | spawn_blocking 内シークレット寿命 — 未対応 |
| F-IROH-09 / F-IROH-31 | relay メタデータ — Phase 3 待ち |
| F-IROH-11 | 複数 ALPN — 未対応 |
| F-IROH-13 | `_s2c_iv` / `_c2s_iv` 未使用 — 未対応 |
| F-IROH-17 | NodeId rotation で cooldown 回避 — 未対応 |
| F-IROH-20 | `cfg!(test)` 混入 — 未対応 (Phase 3 でファイル転送実装時に解消想定) |
| F-IROH-21 | allowlist の role 非対称 — 未対応 |
| F-IROH-23 → F-IROH-28 | multi-client 認証不能 — F-IROH-28 に進化 |

---

## 優先度サマリ

1. **F-IROH-29** 🟡 (silent fail) — passphrase 不一致が運用で気付けない、即時対処
2. **F-IROH-26** 🟡 (target_enc_fp dead code) — 文書化または機能完成
3. **F-IROH-30** 🟡 (chat_loop テスト) — Phase 3 移行前に追加すべき
4. **F-IROH-27** 🟡 (Drop guard async) — テストハング再発防止
5. **F-IROH-32** 🟢 (test-threads 強制) — `serial_test` 導入
6. **F-IROH-28** — Phase 3 でプロトコル拡張検討 (クライアント DSA 公開鍵送信)
7. **F-IROH-31** 🟢 — Phase 3 で `--no-relay` 実装予定 (計画通り)

---

## 関連ドキュメント

- `IROH_MIGRATION_PLAN.md` — 全体計画
- `PHASE1_COMPLETION_REPORT.md` — Phase 1 完了レポート (修正追記版)
- `PHASE1_REMEDIATION_REPORT.md` — Phase 1 修正完了 v1
- `PHASE1_REMEDIATION_REPORT_v2.md` — Phase 1 修正完了 v2
- `PHASE1_REMEDIATION_REPORT_v3_COMPLETE.md` — Phase 1 修正完了 v3 (最終)
- `PHASE1_VERIFICATION_REPORT.md` — v1 検証
- `PHASE1_VERIFICATION_REPORT_v2.md` — v2 検証
- `PHASE1_VERIFICATION_REPORT_v3.md` — v3 検証
- `PHASE2_COMPLETION_REPORT.md` — Phase 2 完了レポート
