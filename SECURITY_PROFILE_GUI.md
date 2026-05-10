
## 1.7 M5: スクリーンショット盗み見対策
- **オプトイン防護**: ユーザ設定（Privacy Mode）により、OS のキャプチャ防止 API を有効化。
  - Windows: `SetWindowDisplayAffinity` (WDA_EXCLUDEFROMCAPTURE)
  - macOS: `NSWindow.sharingType = .none`
- **限界の明記**: 本機能は OS レベルの標準的なキャプチャ（スクショ、録画、画面共有）を制限するものであり、物理的なカメラ撮影や低レイヤの不正プログラムによる取得を完全に防ぐものではない。
- **プラットフォーム制約**: Linux (X11/Wayland) 環境では OS/Compositor 側のセキュリティプロトコル（xdg-desktop-portal 等）に依存し、本アプリからの強制的な制限は行わない。

## 1.8 F1: ファイル選択ダイアログとローカルパスの取り扱い
- **OS ネイティブダイアログ採用**: `rfd` クレート経由で OS 標準のファイル/ディレクトリ選択ダイアログを利用し、独自実装によるパス traversal 露出を回避する。
- **権限の最小化**: ファイル/ディレクトリへのアクセスはダイアログ起動時の OS 権限のみを利用し、アプリ側で広範な FS 走査は行わない。
- **保存ファイル名のバリデーション**: UI 段階で保存ファイル名にパス区切り文字 (`/`, `\`) が含まれる場合、保存処理に渡す前に警告を表示してブロックする (`file_picker::has_invalid_filename_chars`)。
- **保存先ディレクトリの書込権限事前チェック**: `select-save-dir` 経由で取得したパスに対し `std::fs::metadata` で書込権限を確認し、不可なら警告を表示。実書込時の例外を未然に防ぐ。
- **F1 段階の機能スコープ制限**: F1 では UI と picker 経路のみを実装。実ファイル転送 (ALPN_FILE 経由) は F2 以降で実装するため、`File Send`/`File Receive` モードでの Connect ボタンは警告メッセージのみ表示し、ネットワーク処理は起動しない。

## 1.9 F2: GUI Listen workflow とファイル転送
- **CLI 同形プロトコル**: GUI listen は CLI の `--listen` と同じ ALPN_FILE 経路を使用。プロトコル拡張なし。受信側は `run_listen_once` (single-shot) で 1 connection 受け入れて自動 close。
- **`FileIOProvider` 一回限りハンドル**: ファイル handle は `parking_lot::Mutex<Option<tokio::fs::File>>` で保持し、`stdin()` / `stdout()` の最初の呼出しのみ実 handle を返す。2 回目以降は `tokio::io::empty()` / `tokio::io::sink()` を返してリプレイ攻撃で同一ファイルを再送信/再受信できないようにする。
- **構築時 fail-fast**: `FileIOProvider::new_send` は `tokio::fs::File::open` で送信ファイルを async 構築時に open。存在しない/権限不足のパスは listen/connect 開始前に Error として GUI に伝搬。
- **`FileIOProvider::new_recv` の挙動**: `tokio::fs::File::create` を使用、既存ファイルは truncate される。GUI 側で UX 上の上書き confirm が必要な場合は今後の拡張で対応 (現状は filename フィールドを空にして自動命名 `received_<timestamp>.bin` のフォールバックあり)。
- **listen-once cancellation**: GUI の Listen Cancel ボタンは保持している `JoinHandle::abort()` で listen task を強制停止。abort により endpoint と open 中のファイル handle は drop される (tokio + Slint の event loop が個別に cleanup を保証)。
- **CHAT_ACTIVE フラグの取扱い**: `run_listen_once` は chat_mode = false (ALPN_FILE) の場合 CHAT_ACTIVE を取得しない。chat_mode = true (将来的な GUI Chat-Listen) では既存と同様 CHAT_ACTIVE を取得 + drop で release。
- **allowlist / pinned key**: GUI 受信側は `signing_pubkey` (送信者の公開鍵) を任意指定可。指定時は handshake 中に固定鍵検証が動作。未指定 + `allow_unauth = true` で署名なし接続を許容するが、同時に `signing_pubkey` を指定した場合は ALPN フェーズ後の handshake で MITM 検出が動作。
- **F2 段階の UX 制約**: 進捗表示は F3 で実装。F2 段階では `transfer-status` 文字列で「Receiving...」「Sending...」「File received: <path>」を表示するのみ。バイト数進捗は不可視。
