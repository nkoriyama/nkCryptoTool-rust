# 実装レポート — OpenSSL 3.6+ Vendored ビルド導入と RustCrypto 修正

作成日: 2026-05-08
ステータス: 完了 (Verified)

## 概要

環境依存（特に Windows や古い Linux LTS）による「OpenSSL が古くて PQC (ML-KEM/ML-DSA) が動かない」問題を根本的に解決するため、OpenSSL 3.6.2 をソースからビルドして静的リンクする機能を導入しました。また、これに伴い発生していた RustCrypto バックエンドのビルドエラーも修正しました。

## 実施内容

### 1. OpenSSL 3.6+ Vendored ビルドの導入 (`Cargo.toml`)

- **依存関係の追加**: `openssl-src = "300.6"` を追加しました。
    - `openssl` クレートのデフォルト（3.0系）ではなく、ネイティブ PQC 対応の **OpenSSL 3.6.2** が選別されるように明示的に指定しました。
- **新フィーチャーの定義**: `backend-openssl-vendored` を追加。
    - システムの OpenSSL を一切使用せず、すべての PQC 機能を内包した単一バイナリのビルドが可能になりました。

### 2. RustCrypto バックエンドの修正 (`src/backend/rustcrypto_impl.rs`)

- **FIPS 203 API 追従**: `fips203` (v0.4.3) において `DecapsKey` から公開鍵を導出するメソッドが提供されていない問題に対し、FIPS 203 §7.2 で規定されている内部構造（バイト列のオフセット）から公開鍵 (`ek`) を直接抽出するロジックを実装しました。
- **検証**: `cargo test --features backend-rustcrypto` により、KEM の鍵指紋計算などが正しく動作することを確認済みです。

### 3. README.md の更新

- **バックエンド選択ガイド**: `backend-openssl` (System), `backend-openssl-vendored` (Static), `backend-rustcrypto` (Pure Rust) の使い分けガイドを追加しました。
- **ビルド要件の明記**: Vendored ビルドに必要な Perl、Cコンパイラ、NASM (Windows) について記載しました。

## 検証結果

| 項目 | テスト内容 | 結果 |
|---|---|---|
| ビルド | `backend-openssl-vendored` でのコンパイル | ✅ 成功 (OpenSSL 3.6.2 構築確認) |
| PQC 動作 | OpenSSL 3.6 による ML-KEM/ML-DSA 実行 | ✅ 正常 (ネイティブ実装) |
| 回帰テスト | RustCrypto バックエンドでの全テスト | ✅ PASS |
| 相互運用 | OpenSSL(Static) ↔ RustCrypto 間の鍵互換 | ✅ 正常 |

## 結論

今回のアップデートにより、nkCryptoTool は**あらゆる環境（特に Windows）において、複雑なライブラリ設定なしに最新の PQC 機能を利用できる**ようになりました。

これにより、Iroh 移行フェーズにおける「バイナリ配布と環境互換性」の課題が解消されました。
