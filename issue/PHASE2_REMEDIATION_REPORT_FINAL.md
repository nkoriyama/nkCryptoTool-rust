# Iroh 移行フェーズ 2 セキュリティ修正完了レポート v2 (最終)

作成日: 2026-05-06
ステータス: 指摘事項修正完了・包括的検証済み

---

## 実施内容 (再検証レポートに基づく追加修正)

### 1. 指紋生成の堅牢化 (F-IROH-29)
`start()` 時の PQC 鍵指紋生成において、6段ネストの `if let` によるサイレント失敗を廃止し、ヘルパー関数 `get_pqc_fingerprint` を通じてエラーを上位に伝搬させるようにしました。これにより、パスフレーズ不一致や鍵ファイル不在時に Ticket 生成が黙って失敗する問題を解消しました。

### 2. リソース管理とクリーンアップの強化 (F-IROH-27, F-IROH-25)
`EndpointGuard` を改良し、Tokio ランタイムが存在する場合に確実に `Endpoint::close()` を実行するようにしました。また、テスト終了時やエラー発生時も RAII パターンにより適切にクリーンアップが行われるようになり、バックグラウンドタスクによるハングを防止しました。

### 3. Iroh 上の `chat_loop` 検証 (F-IROH-30)
これまでテストされていなかった Iroh トランスポート上での実際の `chat_loop` 動作を検証する E2E テスト `test_iroh_chat_loop_e2e` を追加しました。これにより、QUIC ストリーム上でのフレーム処理、暗号化、タイムアウト制御が正しく機能することを実証しました。

### 4. 並列テストの安定化 (F-IROH-32)
`serial_test` クレートを導入し、グローバルステート（`CHAT_ACTIVE` 等）を共有する Iroh テスト群をシリアル実行するように強制しました。これにより、`--test-threads=1` を手動で指定しなくても、常にクリーンな状態でテストが実行されます。

---

## 検証結果

追加した負例を含む全 6 件の E2E テストが正常にパスすることを確認済みです。

| ID | テスト名 | 検証内容 | 結果 |
|---|---|---|---|
| 01 | `test_iroh_handshake_unauth` | 未認証ピアの接続 | **PASS** |
| 02 | `test_iroh_handshake_auth_success` | 双方向署名検証 | **PASS** |
| 03 | `test_iroh_handshake_auth_fail_invalid_sig` | 署名不正の検知 | **PASS** |
| 04 | `test_iroh_handshake_allowlist_reject` | Allowlist 外拒否 | **PASS** |
| 05 | `test_iroh_handshake_auth_fail_fingerprint_mismatch` | MITM (指紋不一致) 検知 | **PASS** |
| 06 | `test_iroh_chat_loop_e2e` | 実チャットループの完走 | **PASS** |

---

## 結論

Phase 2 は本修正をもって「完了」とします。Ticket フォーマットは計画通りフル機能版へと進化し、PQC 指紋による中間者攻撃対策も E2E で実証されました。

次は **Phase 3 (NAT 越え検証とリレー設定の柔軟化、ファイル転送の移植)** へ移行します。
