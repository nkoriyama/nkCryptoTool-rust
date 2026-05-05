# 第56回 修正レポート（OpenSSL 3.5+ ネイティブ PQC サポートの完全実装）

**日付**: 2026-05-05
**対象**: nkCryptoTool-rust v56
**ステータス**: 実装完了・検証済 (全 24 テスト PASS)

---

## 1. 修正の概要

本サイクルでは、OpenSSL 3.5 以降で導入された ML-KEM (FIPS 203) および ML-DSA (FIPS 204) のネイティブサポートを最大限に活用し、OpenSSL バックエンドにおける PQC 機能を完全に実装しました。これにより、外部プロバイダ（oqs-provider 等）を必要とせず、高性能なアセンブリ実装による PQC 処理が可能となりました。

### 主な変更点
- **ネイティブ Keygen 実装**: `EVP_PKEY_Q_keygen` を用いた高速な KEM/DSA 鍵ペア生成を実装。
- **統一 API シグネチャ**: OpenSSL バックエンドの PQC 関数を、RustCrypto バックエンドと完全に同一の Raw Key 形式（expanded SK 等）で動作するよう統合。
- **抽出ロジックの集約 (F-56-A)**: `extract_raw_private_key` を `utils.rs` に集約。PKCS#8 復号ロジックを一元化し、OpenSSL バックエンドでのサイレント失敗 (F-56-1) を構造的に解消。
- **クロスバックエンド相互運用**: RustCrypto で生成した鍵を OpenSSL で使用する、あるいはその逆のシナリオが変換なしで動作することを実証。
- **安全性と型安全性の向上 (F-56-5/6)**: `pkey_from_raw` の戻り値の型を適正化し、`EVP_PKEY_get_octet_string_param` 後のベクトルを確実に `truncate` する安全処理を追加。
- **パフォーマンスの向上**: OpenSSL バックエンドでの PQC 暗号化速度が約 3.3 GiB/s（ECC 同等）に到達。

---

## 2. 実装詳細

### 2.1 高レベル OpenSSL API の活用 (F-56-1)
低レベルな OID 操作を避け、OpenSSL 3.0 以降の `EVP_PKEY_fromdata` および `OSSL_PARAM` インターフェースを採用しました。
- `pkey_from_raw` ヘルパーを導入し、Raw Byte 列から即座に `EVP_PKEY` オブジェクトを再構築。
- `EVP_PKEY_get_octet_string_param` を用い、生成された鍵から「expanded private key」形式で Raw データを抽出。

### 2.2 構造的リファクタリング (F-56-A)
- 従来はバックエンドごとに重複していた `extract_raw_private_key` を `src/utils.rs` へ移動しました。
- `pkcs8` クレートの `EncryptedPrivateKeyInfo` を用いて、まず暗号化の有無を判定し、パスフレーズが不足している場合は明示的なエラーを返すようにしました。これにより、暗号文を秘密鍵として扱ってしまう事故を未然に防ぎます。

---

## 3. 検証結果

### 3.1 新規テストによる単体検証
`tests/openssl_pqc.rs` を新設し、以下の項目を確認しました。
- ML-KEM-512/768/1024 の生成・カプセル化・復号の往復テスト: **PASS**
- ML-DSA-44/65/87 の生成・署名・検証の往復テスト: **PASS**
- クロスバックエンド相互運用 (RustCrypto ⇔ OpenSSL): **PASS**

### 3.2 統合セキュリティテスト
- `test_preload_encrypted_pem` を OpenSSL バックエンド環境下でも実施し、暗号化 PQC 秘密鍵が正しく復号・ロードされることを確認しました。

### 3.3 ベンチマーク結果 (2GiB データ)
| バックエンド | モード | 暗号化速度 | 復号速度 |
| :--- | :--- | :--- | :--- |
| **OpenSSL** | PQC (ML-KEM-1024) | **~3.2 GiB/s** | **~2.5 GiB/s** |
| **OpenSSL** | Hybrid (PQC + ECC) | **~3.4 GiB/s** | **~2.7 GiB/s** |


---

## 4. ドキュメントの更新

- `README.md` および `SPEC.md` から、OpenSSL バックエンドにおける `oqs-provider` の必要性に関する記述を削除しました。
- 最新のベンチマーク値を `README.md` に反映しました。

本修正により、`nkCryptoTool-rust` は最新の OpenSSL が提供する次世代暗号機能をフルに活用できる、業界最先端のセキュリティツールとしての地位を確固たるものにしました。
