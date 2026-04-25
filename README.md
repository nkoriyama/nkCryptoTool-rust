# **nkCryptoTool (Rust Version)**

**nkCryptoToolは、次世代暗号技術を含む高度な暗号処理をコマンドラインで手軽にセキュアに実行できるツールです。**

Rust版は、C++版の設計思想を継承しつつ、Rustのメモリ安全性とTokioによる高性能な非同期パイプラインを組み合わせて再構築されました。

* **データの暗号化・復号**: 秘密の情報を安全にやり取りできます。
* **認証付き暗号 (AES-256-GCM)**: すべての暗号化処理において、データの機密性に加え、改ざんを検知する完全性も保証するAES-256-GCMモードを採用しています。  
* **デジタル署名・検証**: ファイルの改ざんを検出し、作成者を証明できます。  
* **ECC (楕円曲線暗号)** および **PQC (耐量子計算機暗号)**、さらにRFC 9180の設計思想に基づきPQC (ML-KEM)とECC (ECDH)を組み合わせた**ハイブリッド暗号**に対応。  
* **TPM (Trusted Platform Module) による秘密鍵の保護**: 秘密鍵をマシンのハードウェア (TPM) に紐付けて安全にラッピング保存できます。
* **超高速ストリーミング処理**: Tokioの非同期パイプライン設計により、9GB以上の巨大なファイルも **3GB/s 前後の圧倒的な高速スループット**で安定して処理できます。

## **主な特徴 (Key Features)**

*   **Rust による安全性**: メモリ安全性をコンパイルレベルで保証し、バッファオーバーフローやデータ競合を排除。
*   **Tokio 非同期パイプライン**: `Reader → Crypto → Writer` の3段並列パイプラインにより、I/OとCPU演算の完全なオーバーラップを実現。
*   **相互運用性**: C++版とバイナリレベルで完全な互換性があり、同じ鍵とデータファイルを共有可能。
*   **TPM 2.0 連携**: `tpm2-tools` を介して、ハードウェアレベルでの秘密鍵ラッピングに対応。

## **ビルド方法**

### **依存関係:**

*   **Rust ツールチェーン**: 最新の stable 版推奨 (cargo, rustc)
*   **OpenSSL**: 3.0 以降
    *   **PQC機能**: 相互運用性のために OpenSSL 3.5 以降を推奨。
    *   **TPM機能**: `tpm2-tools` がインストールされ、`/dev/tpmrm0` 等へのアクセス権限があること。

### **ビルド手順:**

```bash
git clone https://github.com/n-koriyama/nkCryptoTool-rust.git
cd nkCryptoTool-rust
cargo build --release
```

*ビルドが成功すると、実行可能ファイルが `target/release/nk-crypto-tool` に生成されます。*

## **使用法**

### **鍵ペアの生成**

* 暗号化鍵ペア (ECC):
  `nk-crypto-tool --mode ecc --gen-enc-key`
* 署名鍵ペア (ECC):
  `nk-crypto-tool --mode ecc --gen-sign-key`
* TPM保護を有効にする場合 (`--use-tpm`):
  `nk-crypto-tool --mode ecc --gen-enc-key --use-tpm`

**Note:** `--passphrase ""` でパスフレーズなし、`--key-dir <path>` で出力先を指定可能。

### **暗号化・復号**

* 暗号化:
  `nk-crypto-tool --mode ecc --encrypt --recipient-pubkey <pub.key> --output-file <enc.bin> <input.txt>`
* 復号:
  `nk-crypto-tool --mode ecc --decrypt --user-privkey <priv.key> --output-file <dec.txt> <enc.bin>`

### **署名・検証**

* 署名:
  `nk-crypto-tool --mode ecc --sign --signing-privkey <priv.key> --signature <file.sig> <input.txt>`
* 検証:
  `nk-crypto-tool --mode ecc --verify --signing-pubkey <pub.key> --signature <file.sig> <input.txt>`

## **パフォーマンス**

9GB の ISO ファイルを用いたベンチマークにおいて、以下の性能を確認済みです（Gen4 NVMe 環境）。

| 処理 | 実行時間 | スループット |
| :--- | :--- | :--- |
| **復号** | **約 3.1 秒** | **約 2.86 GB/s** |
| **暗号化** | **約 3.6 秒** | **約 2.46 GB/s** |

## **ライセンス**

This software is licensed under the GNU Lesser General Public License v3.0.
See the LICENSE.txt file for details.
