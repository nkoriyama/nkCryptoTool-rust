# Iroh 移行フェーズ 1 完了レポート (nkCryptoTool-rust)

作成日: 2026-05-06
ステータス: フェーズ 1 (PoC) 完了

---

## 実施内容

### 1. 依存関係の追加
`Cargo.toml` に以下のクレートを追加しました。
- `iroh`: P2P 通信およびトランスポート層。
- `data-encoding`: Ticket のエンコード用 (Base32)。
- `qrcode`: 接続用 QR コード表示用 (フェーズ 2 で本格利用)。

### 2. モジュール構造の刷新
将来的なトランスポートの拡張性を考慮し、ネットワーク関連のコードをディレクトリ構造に変更しました。
- `src/network.rs` → `src/network/tcp.rs` (レガシー TCP 実装)
- `src/network/iroh.rs` (新規 Iroh 実装)
- `src/network/mod.rs` (ファサード、共通ロジック、および共通型の定義)

### 3. ロジックの共通化と汎用化
TCP 版にあった `chat_loop` や `read_vec` 等の主要ロジックを `AsyncRead` / `AsyncWrite` トレイトに基づき汎用化しました。これにより、TCP と Iroh (QUIC) の両方で全く同じ PQC ハンドシェイクと AEAD チャットロジックを再利用可能になりました。

### 4. CLI の拡張
- `--transport <iroh|tcp>` オプションを追加 (デフォルト: `iroh`)。
- `--listen`: Iroh モード時は NodeId を表示し、接続用 Ticket を出力します。
- `--connect <ticket>`: NodeId ベースの Ticket で接続を試行します。

### 5. PQC ハンドシェイクの実装 (Iroh 上)
- Iroh の `bi-directional stream` 上で、既存の ML-KEM + ML-DSA + ECC ハイブリッドハンドシェイクを移植しました。
- Iroh 自体の TLS 1.3 保護の上に、さらに PQC 層を重ねる二重構造を維持しています。

## 実施内容 (追記: セキュリティ修正)

PoC 実装後の検証により判明した以下のセキュリティ上の欠陥を修正しました。

### 1. クライアント・サーバ認証の再有効化 (F-IROH-01, F-IROH-10)
Iroh トランスポート上でも、TCP 版と同様に ML-DSA による署名検証を実装しました。`--allow-unauth` が false (デフォルト) の場合、正しく署名された鍵を提示しない限り接続は拒否されます。

### 2. チャネルバインディングの導入 (F-IROH-06)
PQC ハンドシェイクのトランスクリプトに、Iroh の NodeId (Local/Remote 両方) を含めるようにしました。これにより、トランスポート層 (TLS 1.3) と PQC 層が強固に紐付けられ、TLS が将来的に破られた場合でも MITM 攻撃を防止できます。

### 3. Allowlist ロジックの移植 (F-IROH-04)
Iroh モードでも、提示された PQC 公開鍵の指紋を `peer_allowlist` と照合するように修正しました。

### 4. セッション管理の改善 (F-IROH-05)
認証成功後にのみチャットセッションをロックするようにし、かつ NodeId ベースでピアを識別するようにしました。

---

## 検証結果 (再検証)

### コンパイル
`cargo check` により、プロジェクト全体が正常にコンパイルされることを確認済み。

### 単体テスト
既存の TCP 版テストケース (cooldown, abort logic 等) が、リファクタリング後も全て `pass` することを確認。

---

## 今後の課題 (フェーズ 2)

- **Ticket フォーマットの完全実装**: PQC 公開鍵の指紋を Ticket に含め、接続開始時に MITM を防止する。
- **QR コード表示**: 端末上に ASCII QR コードを表示し、モバイル端末等からの接続を容易にする。
- **NAT 越えの本格検証**: リレーサーバ経由および Hole-punching による NAT 越えの安定性確認。
