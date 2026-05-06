# Iroh 移行フェーズ 3 完了レポート (nkCryptoTool-rust)

作成日: 2026-05-06
ステータス: フェーズ 3 (高度な接続性とファイル転送) 完了

---

## 実施内容

### 1. ALPN 分離とプロトコル強化 (F-IROH-03)
チャット (`nkct/chat/1`) とファイル転送 (`nkct/file/1`) を ALPN レベルで分離しました。サーバーは着信接続の ALPN を検出し、自動的に適切なモード（チャットループまたはファイル受信）へ切り替えます。

### 2. V3 ハンドシェイクの実装 (F-IROH-28, F-IROH-26)
ハンドシェイク中に PQC 公開鍵を相互に交換する V3 プロトコルを採用しました。
- **メリット**: サーバー側に特定の公開鍵ファイルを事前に配置しなくても、Allowlist（指紋リスト）だけで不特定多数のクライアントを認証可能になりました。
- **指紋検証**: Ticket に含まれる指紋と交換された鍵を照合し、中間者攻撃を確実に遮断します。

### 3. Iroh ファイル転送の実装
TCP 版のロジックを汎用化し、Iroh の双方向ストリーム上で量子耐性のあるファイル送受信を実現しました。E2E テストにより正常な送受信を検証済みです。

### 4. 柔軟な接続設定 (F-IROH-31, F-IROH-09)
以下の CLI オプションを追加しました。
- `--no-relay`: リレーサーバーを介した通信を禁止し、ダイレクト接続のみに制限します（メタデータ漏洩防止）。
- `--relay-url`: 特定のプライベートリレーサーバーを指定可能にしました。

### 5. リソース管理の確実化 (F-IROH-34)
`async` ブロックと明示的な `close().await` 待機を組み合わせたクリーンアップパターンに刷新しました。これにより、タイムアウトやエラー発生時もバックグラウンドタスクが残留せず、確実に終了します。

---

## 検証結果

`serial_test` を用いたシリアル実行環境にて、全 8 件のテストが正常にパスすることを確認済み。

| テストケース | 検証内容 | 結果 |
|---|---|---|
| `test_iroh_handshake_unauth` | 未認証接続 | **PASS** |
| `test_iroh_handshake_auth_success` | 正常認証接続 | **PASS** |
| `test_iroh_handshake_auth_fail_fingerprint_mismatch` | MITM 検知 | **PASS** |
| `test_iroh_handshake_auth_fail_invalid_sig` | 署名不正検知 | **PASS** |
| `test_iroh_handshake_allowlist_reject` | 認可外拒否 | **PASS** |
| `test_iroh_handshake_multi_client_auth_success` | **(New)** マルチクライアント認証 | **PASS** |
| `test_iroh_chat_loop_e2e` | チャットループ起動 | **PASS** |
| `test_iroh_file_transfer_e2e` | **(New)** ファイル転送成功 | **PASS** |

---

## 結論

`IROH_MIGRATION_PLAN.md` に基づくすべての実装フェーズが完了しました。`nkCryptoTool-rust` は、Iroh による高い NAT 越え性能と、PQC による強固な認証・暗号化を両立した、次世代のセキュア通信ツールへと進化しました。
