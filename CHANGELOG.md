# Changelog

All notable changes to this project will be documented in this file.

## [2.1.0-rc1] - 2026-05-10

### Added
- **Transfer Mode Toggle (Phase 4 F1)**: GUI に Chat / File Send / File Receive の 3 択モード切替を追加 (`TransferMode` enum + `transfer-mode` プロパティ)。
- **Native File Dialogs (Phase 4 F1)**: `rfd` クレート経由で OS ネイティブのファイル/ディレクトリ選択ダイアログを統合。`gui-file-transfer` feature 配下で有効化。
- **`FilePickerProvider` trait**: ダイアログ起動経路をテストから差替可能にする抽象化 (Rfd / Noop / Mock 実装)。
- **保存ファイル名 UI 検証**: `/` `\` を含むファイル名入力に対する事前警告 (`file_picker::has_invalid_filename_chars`)。
- **保存先ディレクトリ書込権限チェック**: 選択時に `metadata` 経由で writable を確認しエラー表示。
- **GUI Listen Workflow (Phase 4 F2)**: FileReceive モードで GUI が listen 側として動作。「Generate Ticket and Wait」ボタンで ticket を生成・表示し、incoming 接続を 1 回 accept して自動 close。
- **`FileIOProvider` (Phase 4 F2)**: `src/network/mod.rs` にファイル backed の IOProvider を追加。`new_send` / `new_recv` で async 構築時にファイル handle を pre-open し、`stdin()` / `stdout()` の最初の呼出しのみ実 handle を返す one-shot方式。
- **`NetworkProcessor::run_listen_once` (Phase 4 F2)**: single-shot listen API。ticket 生成後に on_ticket callback を発火、接続後に handshake 完了で on_handshake_done callback を発火、receive_file または chat_loop を 1 回実行して endpoint close。
- **`NetworkProcessor::start_with_ticket_callback` (Phase 4 F2)**: 既存 `start()` のリファクタ。ticket をコールバック経由で公開して GUI / CLI 両方で再利用可能化。
- **GUI File Send 統合 (Phase 4 F2)**: FileSend モードで Connect ボタン押下時、選択ファイルを `FileIOProvider::new_send` で開き、`run_connect_with_handshake_callback` 経由で送信。
- **GUI File Transfer UI (Phase 4 F2)**: `listening` / `generated-ticket` / `file-transfer-active` / `transfer-status` プロパティと `listen-display-visible` / `file-transfer-visible` / `connection-settings-visible` 計算プロパティで listen / 転送中 / 完了の状態遷移を UI に反映。
- **File Transfer Progress (Phase 4 F3)**: ファイル転送中の進捗状況をリアルタイムで表示する機能を実装。`transfer-progress` (0.0〜1.0) / `transfer-bytes` / `transfer-total` プロパティを介して ProgressBar および詳細な転送済みバイト数を表示。
- **進捗コールバック API (Phase 4 F3)**: `send_file_with_progress` および `receive_file_with_progress` を `src/network/mod.rs` に追加。64KiB 単位のチャンクベースで非同期コールバックを発火。

### Notes
- Cargo.toml version は v2.0.4 据置。F1〜F4 完了後に v2.1.0 として release tag を切る。

## [2.0.4] - 2026-05-10

### Fixed
- **GUI handshake callback actually invoked**: The `run_connect_with_handshake_callback` API added in v2.0.3 declared the `on_handshake_done` parameter but never invoked it. Now wraps the FnOnce in `Option` and calls it after handshake completes, before `chat_loop` begins. This restores the intended UI transition: `Connect` → chat panel immediately (not after disconnect).
- **GuiStdin buffer overflow panic**: `GuiStdin::poll_read` previously called `buf.put_slice(&data)` directly, which panics when the channel-received `Vec<u8>` is larger than `buf.remaining()` (e.g. typing "hello\n" into a 1-byte read buffer). Refactored to a pending-buffer model: drain into local `VecDeque` first, then write up to `buf.remaining()` per poll. This eliminates the immediate "Connection closed by peer" disconnect on first message send.
