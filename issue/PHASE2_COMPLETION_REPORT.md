# Iroh 移行フェーズ 2 完了レポート (nkCryptoTool-rust)

作成日: 2026-05-06
ステータス: フェーズ 2 (Ticket 完全版) 完了

---

## 実施内容

### 1. Ticket フォーマットの完全実装 (F-IROH-02, F-IROH-19)
`IROH_MIGRATION_PLAN.md` の仕様に基づき、バイナリベースの新しい Ticket フォーマットを `src/ticket.rs` に実装しました。
- **構造**: `nkct1` プレフィックス + Base32 エンコード。
- **ペイロード**: バージョン、NodeId、リレーURL、直接接続アドレス（IPv4/IPv6）、PQC 公開鍵指紋（SHA3-256）、および CRC32 チェックサム。
- **メリット**: NodeId だけでなく接続に必要なアドレス情報が同梱されるため、接続成功率が大幅に向上。また、PQC 鍵の指紋を事前に共有することで MITM 攻撃を検知可能。

### 2. MITM 検知機能の有効化
`--connect <ticket>` を実行する際、Ticket に含まれる PQC 公開鍵の指紋を抽出し、ハンドシェイク中に提示された相手の公開鍵と照合するロジックを実装しました。指紋が一致しない場合、即座に接続を遮断します。

### 3. QR コード表示の実装
`--listen` 時に、生成された Ticket を QR コード（ASCII アート）として標準エラー出力に表示するようにしました。これにより、モバイル端末や他の PC からの接続が容易になります。

### 4. CLI 引数エイリアスの追加
ユーザー利便性のため、以下のエイリアスを `Args` に追加しました。
- `--my-sign-key` (alias for `--signing-privkey`)
- `--my-enc-key` (alias for `--user-privkey`)

### 5. 包括的なセキュリティテストの拡充 (F-IROH-12)
ハッピーパスに加えて、以下の負例テストを追加し、セキュリティ境界が正しく機能することを検証しました。
- `test_iroh_handshake_auth_fail_fingerprint_mismatch`: MITM (指紋不一致) の検知。
- `test_iroh_handshake_auth_fail_invalid_sig`: 署名不正の検知。
- `test_iroh_handshake_allowlist_reject`: Allowlist による拒否。

---

## 検証結果

`cargo test -- --test-threads=1` にて全 5 件の Iroh E2E テストが正常にパスすることを確認済み。

| テストケース | 内容 | 結果 |
|---|---|---|
| `test_iroh_handshake_unauth` | 認証なし接続 | **PASS** |
| `test_iroh_handshake_auth_success` | 正常な認証接続 | **PASS** |
| `test_iroh_handshake_auth_fail_fingerprint_mismatch` | 指紋不一致（MITM）検知 | **PASS** |
| `test_iroh_handshake_auth_fail_invalid_sig` | 署名不正検知 | **PASS** |
| `test_iroh_handshake_allowlist_reject` | 認可外拒否 | **PASS** |

---

## 次のステップ (フェーズ 3)

- **NAT 越えの本格検証**: 異なるネットワーク間（モバイル回線等）での接続安定性確認。
- **リレー設定の柔軟化**: `--no-relay` オプションや自前リレー指定の実装。
- **ファイル転送の実装**: `todo!()` となっているファイル転送ロジックの Iroh 移植。
