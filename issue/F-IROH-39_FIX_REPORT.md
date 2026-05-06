# F-IROH-39 修正レポート — chat_loop の stdin EOF 無限ループ解消

作成日: 2026-05-06
ステータス: 修正完了 (Verified)

## 概要

`chat_loop` において、標準入力 (stdin) が EOF (Ctrl-D, パイプ終了, SSH 切断等) に到達した際、プログラムが終了せずに tight loop (CPU 100% 占有) に陥る致命的なバグを修正しました。

## 根本原因

`read_line_secure` 関数が EOF と空行入力を共に `Ok(0)` という戻り値で返していたため、呼び出し側の `chat_loop` でこれらを区別できず、EOF 後も `continue` によって即座に次の読み取りを試行し続けていました。

## 修正内容

### 1. 状態管理の厳密化 (`src/network/mod.rs`)
新たに `LineRead` 列挙型を導入し、読み取り結果を明示的に区別するようにしました。

```rust
pub enum LineRead {
    Line,       // 改行で終わる行 (空行含む)
    PartialEof, // 改行なしで EOF に到達 (残データあり)
    Eof,        // 0 バイトで EOF に到達
}
```

### 2. `read_line_secure` の変更
戻り値を `Result<LineRead>` に変更し、EOF 到達時に `LineRead::Eof` または `LineRead::PartialEof` を返すようにロジックを修正しました。

### 3. `chat_loop` のリファクタリングと制御フロー修正
- `chat_loop` が標準入力 (`stdin`) を引数として受け取るようにリファクタリングしました。これにより、テスト時に `tokio::io::empty()` を流し込むことが可能になり、インタラクティブな入力を待たずにテストを完結できるようになりました。
- `read_line_secure` の結果に基づき、以下の挙動を実装しました：
    - `LineRead::Eof`: 即座にループを終了し、接続をクローズする。
    - `LineRead::PartialEof`: バッファに残っているデータを送信した後、ループを終了する。
    - `LineRead::Line` (空行): プロンプトを再表示して入力を待機する (従来通り)。

## 検証結果

### ユニットテスト
`src/network/mod.rs` に以下のテストを追加し、すべてパスすることを確認しました：
- `test_read_line_secure_eof`: 即時 EOF 時の挙動
- `test_read_line_secure_line`: 通常の改行あり入力
- `test_read_line_secure_partial_eof`: 改行なし EOF 時のデータ保持
- `test_read_line_secure_empty_line`: 空行 Enter 時の挙動

### 回帰テスト
- 以前はバグ（無限ループ）によるタイムアウトを期待していた `test_iroh_chat_loop_smoke` を、正常終了を期待するように修正しました。
- `cargo test --lib network` を実行し、既存のテストおよび新規テスト（全 21 件中、フィルタリング等を除いた関連分）がすべてパスすることを確認しました。

### 実機回帰確認
- 以前は EOF 時に CPU 100% とログの肥大化（2.5MB超）が発生していましたが、修正後は正常に終了し、ログも最小限（115B程度）に抑えられることを確認しました。

### マルチバックエンド確認
- `backend-openssl` (デフォルト) および `backend-rustcrypto` の両方でビルドおよびテスト全件パスを確認しました。
- `backend-rustcrypto` において `fips203` の API 仕様変更（get_public_key の不在）に起因するビルドエラーを、FIPS 203 §7.2 に基づくオフセット抽出により修正しました。

## 影響範囲
- `TransportKind::Tcp` および `TransportKind::Iroh` の両方のチャットモードにおいて、正常に EOF 終了が可能になりました。
- 非対話的なスクリプト（パイプ利用）での動作が安定しました。
