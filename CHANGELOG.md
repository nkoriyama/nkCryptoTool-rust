# Changelog

All notable changes to this project will be documented in this file.

## [2.2.0] - 2026-08-30

2.1.0 から 60 の PR。crates.io への初回公開バージョンでもある。

### Breaking

- **実行ファイル名と crate 名を `nkct` に変更**: `nk-crypto-tool` から改名した。crates.io の
  crate 名も `nkct`（`cargo install nkct`）。旧名では入らない。呼び出しているスクリプト・
  systemd unit・alias は書き換えが必要。C-ABI 共有ライブラリも `libnkct.so` になる。
- **`--peer-allowlist` を廃止**: 認可は keyring の grants テーブルに一本化。平文の allowlist ファイルは読まれない。
- **`GRANT_ALL` の既定を廃止**: ペアリングで登録した相手に自動で全権が付かなくなった。keyring 経由の shell は明示的なポリシーを要求する。
- **TCP トランスポートを削除**: P2P は iroh (QUIC) のみ。
- **暗号ファイル v2 形式の削除**: 自前実装の AEAD を検証済みの one-shot API に置換した際に撤去 (監査 M5)。v3 のみを読む。
- **`--listen` → `--serve-chat`**: 全サーバの語彙を `serve-*` に統一。`--listen` は alias として残置。
- **SQLCipher → redb**: MLS / inbox / keyring のストアが純 Rust の redb に移行。`mls` は C 依存ゼロになりモバイルでビルドできる。旧 SQLCipher DB からの移行は `legacy-sqlcipher-migration` feature の移行ツールで行う。

### Added

- **MLS グループチャット (P1–P8)**: RFC 9420 ベース。Ed25519+ML-DSA-65 のハイブリッド署名、X25519+ML-KEM-768 のハイブリッド KEM (X-Wing)、remove_member と PCS、`nkct/mls/1` 越しの KeyPackage / Welcome、3 者ディスパッチ、Slint GUI、グループ内ファイル転送、グループ別アドレス帳、`mls rekey`。
- **P2P シェル (Phase 0–6)**: 踏み台レスの PTY ブリッジ。認可ポリシーとコマンド allowlist、監査ログ、レート制限、setuid 権限降格、`--tui` ステータスバー (接続メトリクス / ハイブリッド秘匿スタック表示)、Windows (ConPTY) 対応、MLS グループ membership の shell/forward ポリシーへの投影。
- **P2P scp (`nkct/scp/3`)**: 再帰転送 (`-r`)、`user=` ポリシー、レジューム付き get、ライブ進捗バー、put パイプライン化。
- **P2P ポートフォワード (Phase 3–5)**: `nkct/fwd/1` 上の多重化ローカル転送、リモートフォワード (`-R`)、SSH 風クレジットウィンドウによるチャネル毎フロー制御。
- **GPG 風 keyring (my-identities)**: 自分の鍵を keyring.db に封入。生成 / 復号 / 署名 / KeyBundle / P2P identity のすべてが鍵ファイル無しで動く (`gen-my-key`, sign 側の auto-match, keyring 由来のハンドシェイク identity)。
- **ペアリング (`nkct/pairing/1`)**: `ssh-copy-id` 相当の KeyBundle 自動登録。
- **PQ-FS / One-Time Prekey**: 静的 identity 鍵と署名付き recipient bundle、inbox 越しのワンショット封筒、PUBLISH/FETCH と NodeId 毎のレート制限、inbox COUNT による自動補充。
- **at-rest 暗号化**: DEK を AES-256-GCM でラップ (suite 0xF102)、KEK を DB に束縛して KEK すり替えを封じ、アンチロールバックカウンタを KEK に結合、TPM 2.0 NV カウンタ対応。
- **inbox store-and-forward (`nkct/inbox/1`)**: 保存時暗号化、ロールバックチェックポイント。
- **v3 チャンク化ストリーミング AEAD 形式** (`StreamingAeadProcessor`)。
- **`--qr`**: 任意の文字列を端末に QR 表示（外部ツール不要）。
- **モバイル**: UniFFI ブリッジと `MobileChatClient`、Android の Kotlin アプリ骨格。
- **P2P 運用系**: mDNS ローカル探索 (`--discovery local`)、永続ノード鍵による安定 NodeId、admission control の環境変数設定、n0 公開インフラにメタデータが渡る場合の警告。
- **Windows 対応**: shell (portable-pty)、`secure_fs` によるファイル安全性ハードニング、scp confinement の post-open 実パス再検証、CI。

### Platforms

初回の crates.io 公開に合わせ、リリース成果物を 2 つから 4 つに増やした。

| 対象 | 成果物 | 再現ビルド |
|---|---|---|
| Linux x86_64 | 静的 musl | あり |
| Linux arm64 | 静的 musl | あり |
| Windows x86_64 | `.exe` | なし |
| macOS | universal (arm64 + x86_64) | なし |

- **macOS**: CI で一度もビルドされていなかった。保留の根拠は「ring 0.17 aarch64-darwin の
  問題」とだけ記録されていたが、advisory ジョブを入れて実際に走らせたところ両 Apple ターゲット
  のビルド・clippy・**257 テスト全通過**。根拠は陳腐化していた。`src/scp.rs` の `F_GETPATH`
  による fd 再検証（Linux の `/proc/self/fd` と同格）は、このジョブができるまでどのターゲット
  でもコンパイルされたことがなかった（Rust は無効な `cfg` 分岐を型検査しないため）。
- **Linux arm64**: 258 テスト全通過。CPU フロアは crypto 拡張を**要求しない**。CI の arm64
  ランナーはサーバ級で拡張を持つため、フロアの誤りは CI では検出できない。実際に Raspberry
  Pi 4 上でクロスビルド版の ML-DSA-65 + ML-KEM-768 往復（AES-GCM / ChaCha20 とも）を確認した。
- 両プラットフォームとも CI ジョブを release-blocking にした。成果物を配る以上、失敗を
  握り潰す設定のままにはできない。
- Windows と macOS が再現ビルドでないことは、リリースノートと README に明記する。

### Changed

- **既定バックエンドを RustCrypto に**: プラットフォーム依存を減らし移植性を優先。OpenSSL は明示的な opt-in。
- **性能**: `aes-gcm` 0.11 世代への移行でファイルスループット +50〜60%。v3 チャンクの暗号化・復号でバッファ再利用と in-place 化、scp の bulk Data フレームを in-place で seal、QUIC 受信ウィンドウを 8 MiB に拡大、MLS ブロードキャストの並列ファンアウト。

### Fixed

- **P2P シェルの正常終了がエラー表示になっていた**: セッション終了時、サーバは `Frame::Exit`
  を書いた直後に戻り、呼び出し側が即座に `endpoint.close()` する。QUIC の CONNECTION_CLOSE は
  未確認のデータを捨てるので Exit フレームが失われ、クライアントは読み取りエラーを見る。
  クライアントの受信ループは「同期ずれをクリーンな切断に見せない」ため設計上あらゆる受信
  エラーを表示するので、Ctrl+D による普通の終了が
  `session ended: inbound frame decode failed: connection lost` と表示され、終了コードは 255
  になっていた。サーバは Exit 送信後に送信ストリームを finish し、クライアントが自分側を
  閉じるのを上限つきで待つようにした（相手の EOF が配送完了の証拠。固定の sleep より厳密で、
  実測でも待ち時間は増えない）。

### Security

2026-07 監査の 21 件と 2026-07-28 再スキャンの 5 件を含め、33 のセキュリティコミット。主なもの:

- 認証前のリソース枯渇: inbox DEPOSIT フラッド (H1) と POLL バッチのバイト数上限、容量到達時は退避ではなく拒否、prekey 公開のコスト下限、accept の pre-auth / session プール分離 (H2)。
- MLS: Commit / Proposal を signed cleartext ではなく PrivateMessage として封緘。SYNC 履歴を要求者自身の join epoch にクランプ。ファンアウトをそのグループに限定し、Remove 済みのロスターが保証を持ち越せないようにした。
- 鍵と形式: ECC 秘密鍵をパスフレーズで暗号化し PBKDF2 を 600k に (H1/H3)、Ticket パースの境界チェック (H2, DoS panic)、v2 IV 長 panic (M2)、ticket fingerprint バイパス (M3)。
- ファイルシステム: 受信ファイルを一時領域に置き AEAD タグ検証後にのみコミット、受信先ディレクトリの封じ込めを文字ブラックリストではなく `Path` で判定、中間 symlink の TOCTOU を Linux 以外にも拡張 (M4)。
- メモリ: `SecureBuffer` の munlock リーク修正、TPM 鍵一時ファイルの安全消去。
- リリースゲート自体の監査: ワークフローを grep ではなくパースして判定、ベースラインゲートにファイル集合の表明とフロアを追加。

### Notes

- ライブラリターゲット (`rlib` / `cdylib`) は bin とモバイル FFI シムのために存在するもので、**公開 API ではない**。semver 保証の対象外。
- Linux のリリースバイナリは `packaging/reproducible-build.sh` による再現可能ビルドで作られる。

## [2.1.0] - 2026-05-10

### Added
- **Transfer Mode Toggle (Phase 4 F1)**: GUI に Chat / File Send / File Receive の 3 択モード切替を追加 (`TransferMode` enum + `transfer-mode` プロパティ)。
- **Native File Dialogs (Phase 4 F1)**: `rfd` クレート経由で OS ネイティブのファイル/ディレクトリ選択ダイアログを統合。`gui-file-transfer` feature 配下で有効化。
- **`FilePickerProvider` trait**: ダイアログ起動経路をテストから差替可能にする抽象化 (Rfd / Noop / Mock 実装)。
- **保存ファイル名 UI 検証**: `/` `\` を含むファイル名入力に対する事前警告 (`file_picker::has_invalid_filename_chars`)。
- **保存先ディレクトリ書込権限チェック**: 選択時に `metadata` 経由で writable を確認しエラー表示。
- **GUI Listen Workflow (Phase 4 F2)**: FileReceive モードで GUI が listen 側として動作。「Generate Ticket and Wait」ボタンで ticket を生成・表示し、incoming 接続を 1 回 accept して自動 close。
- **`FileIOProvider` (Phase 4 F2)**: `src/network/mod.rs` にファイル backed の IOProvider を追加。`new_send` / `new_recv` で async 構築時にファイル handle を pre-open し、`stdin()` / `stdout()` の最初の呼出しのみ実 handle を返す one-shot 方式。
- **`NetworkProcessor::run_listen_once` (Phase 4 F2)**: single-shot listen API。ticket 生成後に on_ticket callback を発火、接続後に handshake 完了で on_handshake_done callback を発火、receive_file または chat_loop を 1 回実行して endpoint close。
- **`NetworkProcessor::start_with_ticket_callback` (Phase 4 F2)**: 既存 `start()` のリファクタ。ticket をコールバック経由で公開して GUI / CLI 両方で再利用可能化。
- **GUI File Send 統合 (Phase 4 F2)**: FileSend モードで Connect ボタン押下時、選択ファイルを `FileIOProvider::new_send` で開き、`run_connect_with_handshake_callback` 経由で送信。
- **GUI File Transfer UI (Phase 4 F2)**: `listening` / `generated-ticket` / `file-transfer-active` / `transfer-status` プロパティと `listen-display-visible` / `file-transfer-visible` / `connection-settings-visible` 計算プロパティで listen / 転送中 / 完了の状態遷移を UI に反映。
- **`ProgressCallback` type alias (Phase 4 F3)**: `pub type ProgressCallback = Arc<dyn Fn(u64, Option<u64>) + Send + Sync>` を `src/network/mod.rs` に追加。CLI / GUI 両方で進捗監視に利用可能。
- **`send_file_with_progress` / `receive_file_with_progress` (Phase 4 F3)**: 既存 `send_file` / `receive_file` を `_with_progress(_, _, _, _, _, None)` の薄ラッパに refactor。新 API は `64 KiB chunk counter` で進捗発火を制限。
- **`run_connect_with_handshake_callback_and_progress` / `run_listen_once_with_progress` (Phase 4 F3)**: iroh.rs の connect / listen API に進捗コールバック転送を追加。既存 API は `_with_progress(_, _, None)` の薄ラッパとして維持、CLI 互換性確保。
- **GUI 進捗 UI (Phase 4 F3)**: Slint UI に `transfer-progress` (float 0.0〜1.0) / `transfer-bytes` / `transfer-total` プロパティ + `ProgressIndicator` widget を統合。FileSend は `metadata().len()` から total を取得して進捗 % を表示、FileReceive は total 不明のため indeterminate animation。
- **`make_progress_pipeline` (Phase 4 F3)**: `tokio::sync::mpsc::channel(1)` ベースの latest-wins 進捗 channel + Slint pump task。`format_transfer_status` で「`<sent>/<total> bytes (<percent>%)`」形式の status 文字列を生成。

### Notes
- Cargo.toml version は v2.0.4 据置。F1〜F4 完了後に v2.1.0 として release tag を切る。
- F3 段階では転送速度 / ETA は未表示。必要なら F3.5 か v2.2 で追加検討 (handoff §1.2 F3-O1〜O3 推奨機能)。

### Known Issues / 既知の制限事項 (Gemini Trigger 3 §3.1 反映)
- **転送中キャンセル未対応 (v2.2 持ち越し)**: GUI File Send / File Receive 進行中に "cancel" 操作なし。途中で中断したい場合は **アプリケーションを終了する** (プロセス kill) こと。Listen 段階の cancel は実装済 (`listen-cancel` callback)。
- **後方互換性のスコープ**: F4 で iroh QUIC FIN race fix (writer.shutdown 追加) を適用。新版 sender は graceful close を送り、receiver の挙動は新旧両 sender に対して同一だが、未知の互換性 corner case を避けるため **CLI/GUI 共に v2.1.x 同士の組合せを推奨**。v2.0.x sender ↔ v2.1.x receiver の混在運用は明示的にはサポート対象外。
- **巨大ファイル UI 制限**: 10 GB 超のファイルは GUI File Send で開始前に reject 表示。`MAX_FILE_SIZE = 10 GiB` (`src/network/mod.rs`)。
- **CI 上で flaky な内部 test 8 件**: `src/network/iroh.rs` の `test_iroh_*` は `#[ignore]` で marking 済 (build-env では reliable に PASS)。CI には advisory として `cargo test -- --ignored` step あり。詳細は `PHASE5_ROADMAP.md §3.3`。
- **subprocess-based e2e test (test_pqc_e2e_cycle / test_hybrid_e2e_cycle)**: GitHub Actions ubuntu runner で原因不明の non-zero exit 失敗、`#[ignore]` で marking。build-env では PASS。`PHASE5_ROADMAP §3.x` で v2.2 調査予定。

## [2.0.4] - 2026-05-10

### Fixed
- **GUI handshake callback actually invoked**: The `run_connect_with_handshake_callback` API added in v2.0.3 declared the `on_handshake_done` parameter but never invoked it. Now wraps the FnOnce in `Option` and calls it after handshake completes, before `chat_loop` begins. This restores the intended UI transition: `Connect` → chat panel immediately (not after disconnect).
- **GuiStdin buffer overflow panic**: `GuiStdin::poll_read` previously called `buf.put_slice(&data)` directly, which panics when the channel-received `Vec<u8>` is larger than `buf.remaining()` (e.g. typing "hello\n" into a 1-byte read buffer). Refactored to a pending-buffer model: drain into local `VecDeque` first, then write up to `buf.remaining()` per poll. This eliminates the immediate "Connection closed by peer" disconnect on first message send.

### Phase 3 Status
- v2.0.4 marks Phase 3 as **build-verified + E2E-verified**: GUI builds, runs, and successfully exchanges messages bidirectionally over Iroh PQC chat. Self-loopback test (CLI listener + GUI connector) confirms full round-trip messaging.

## [2.0.3] - 2026-05-10

### Added
- **`run_connect_with_handshake_callback` API**: Extended `NetworkProcessor` with a callback parameter intended to fire after handshake but before `chat_loop` blocks, to enable GUI state transition. (Note: the callback was not actually invoked in v2.0.3; this was fixed in v2.0.4.)

### Fixed
- **CHAT_ACTIVE flag reset on session end**: The session-active flag is now explicitly reset on chat_loop completion (both Ok and Err paths), preventing "Chat session already active" errors on reconnect attempts after abnormal disconnects.

## [2.0.2] - 2026-05-10

### Fixed
- **Slint Property Bugs**: Corrected property modifiers in \`chat.slint\` from \`in\` to \`in-out\` for properties modified by internal UI logic (buttons, accepted handlers).
- **Thread Safety**: Refactored GUI background tasks to avoid capturing \`!Send\` Slint handles across \`.await\` points.
- **Error Mapping**: Fixed boxed error mapping in \`main.rs\` to satisfy \`anyhow\` bounds.
- **M2 Implementation Fixes**: Resolved various compilation errors in camera and QR scanning logic (incorrect method names, missing casts, missing features).

### Added
- **Testing Feature**: Added \`testing\` feature to expose library mocks for integration tests.

## [2.0.1] - 2026-05-09

### Fixed
- **M5 test coverage completion**: Added missing tests for Linux no-op and unsupported OS warnings.

### Documentation
- **SECURITY_PROFILE_GUI restoration**: Restored §1.5 (M2 QR threats) and §1.6 (M4 notification threats).

## [2.0.0] - 2026-05-09

### Added
- **Phase 3 GUI Completion**: Final stabilization of the Slint-based graphical user interface.
- **Privacy Mode (M5)**: Integrated screen capture prevention for Windows and macOS.
- **Unified GUI Binary**: The application now supports a full-featured graphical mode via the \`--gui\` flag.

### Changed
- **Major Version Upgrade**: Transitioned to v2.x to mark official GUI support.

## [1.0.0] - [1.4.1]
(See git history for older entries)
