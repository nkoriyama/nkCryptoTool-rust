
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
- **CLI 同形プロトコル**: GUI listen は CLI の `--serve-chat` と同じ ALPN_FILE 経路を使用。プロトコル拡張なし。受信側は `run_listen_once` (single-shot) で 1 connection 受け入れて自動 close。
- **`FileIOProvider` 一回限りハンドル**: ファイル handle は `parking_lot::Mutex<Option<tokio::fs::File>>` で保持し、`stdin()` / `stdout()` の最初の呼出しのみ実 handle を返す。2 回目以降は `tokio::io::empty()` / `tokio::io::sink()` を返してリプレイ攻撃で同一ファイルを再送信/再受信できないようにする。
- **構築時 fail-fast**: `FileIOProvider::new_send` は `tokio::fs::File::open` で送信ファイルを async 構築時に open。存在しない/権限不足のパスは listen/connect 開始前に Error として GUI に伝搬。
- **`FileIOProvider::new_recv` の挙動**: `tokio::fs::File::create` を使用、既存ファイルは truncate される。GUI 側で UX 上の上書き confirm が必要な場合は今後の拡張で対応 (現状は filename フィールドを空にして自動命名 `received_<timestamp>.bin` のフォールバックあり)。
- **listen-once cancellation**: GUI の Listen Cancel ボタンは保持している `JoinHandle::abort()` で listen task を強制停止。abort により endpoint と open 中のファイル handle は drop される (tokio + Slint の event loop が個別に cleanup を保証)。
- **CHAT_ACTIVE フラグの取扱い**: `run_listen_once` は chat_mode = false (ALPN_FILE) の場合 CHAT_ACTIVE を取得しない。chat_mode = true (将来的な GUI Chat-Listen) では既存と同様 CHAT_ACTIVE を取得 + drop で release。
- **allowlist / pinned key / 送信者身元 (F12 修正後)**: 受信 listener の config は `gui::build_file_receive_config` が一箇所で組み立てる。
  - `signing_pubkey` (「Public Key Path (expected sender, optional)」) を指定した場合は handshake の #6 が固定鍵に束縛され、その鍵以外は handshake を完了できない (pin)。このとき node は open ではないので `allow_unauth = false`。
  - 未指定 (既定フロー) の場合、keyring も pin も無いので「ticket を持つ者は誰でも繋げる」= `allow_unauth = true` と正直に宣言する。**ただし `require_initiator_self_auth = true` により、`INITIATOR_SELF_AUTH` を立てない匿名 peer は handshake で拒否される**。修正前は `allow_unauth = true` のみで匿名接続を受理し、送信者が誰かを知る手段が一切無いまま保存先へ書き込んでいた。
  - 署名要求は「ticket 漏洩時に第三者を締め出す」ものではない (攻撃者は自分で鍵を作れる)。得られるのは **セッションが必ず identity を持つ** ことであり、その fingerprint を UI に出して口頭等で照合できる点にある。
  - keyring allowlist は listener 起動時に `preload_allowlist()` を呼んで有効化する。GUI には keyring 指定 UI が無いため `keyring_db = None` で実質 no-op だが、設定された場合に無視されない配線にしてある。
- **送信側 (Connect / File Send) の鍵フィールド**: 送信側 config も `gui::build_connect_config` が一箇所で組み立て、passphrase 再入力後の再接続もこれを共有する。**空欄は「未指定」= `None`** であり、`Some("")` にはしない。`signing_privkey.is_some()` はパスの有無ではなく `has_signing_identity` そのもの (handshake #5 の `INITIATOR_SELF_AUTH` を立ててから #6 と `sig_I` を作る)、`signing_pubkey.is_some()` は「responder pin を持つ」宣言 (`EXPECTS_RESPONDER_AUTH` + #7 の fingerprint 事前 commit) であり、いずれも空文字を鍵ファイルとして読む前に**宣言として読まれる**ため、`Some("")` は偽の申告になる。
  - 帰結として、鍵未設定の GUI 送信は **GUI 受信 (上記 F12 の `require_initiator_self_auth = true`) に対しては成立しない**。ticket に responder fingerprint がある場合は handshake で "Client authentication required" として拒否され、無い場合は接続前にローカルで「pin も `allow_unauth` も無い」として拒否される。identity を要求するのが F12 の意図であり、これは仕様どおりの拒否である。**GUI ↔ GUI で送るには送信側に署名鍵の設定が要る。**
  - 一方 `--allow-unauth` で待ち受ける CLI 受信に対しては、匿名接続として成立しうる (これは正当な構成であり、GUI 側でのローカル事前拒否は行わない)。ただし成立には **CLI 受信側が署名鍵を持っていること**が要る — その fingerprint が ticket に載って初めて GUI 送信側の `has_responder_pin` が真になる。GUI 送信側自身の `allow_unauth` は常に false なので、鍵無しの `--allow-unauth` 受信に対しては、GUI 側が接続前に自分を拒否する。
- **接続相手の表示**: handshake 完了コールバックが peer の ML-DSA fingerprint (`Option<[u8; 32]>`) を受け取り、`gui::format_peer_identity` で整形して `peer-fingerprint` プロパティに表示する。生バイト 32 byte の固定長 hex (64 文字) なので peer が文字列を制御できず、terminal sanitize は不要。転送完了後もクリアされず、次の「Generate Ticket and Wait」押下時にクリアされる (事後照合のため)。
- **F2 段階の UX 制約**: 進捗表示は F3 で実装。F2 段階では `transfer-status` 文字列で「Receiving...」「Sending...」「File received: <path>」を表示するのみ。バイト数進捗は不可視。

## 1.10 F3: ファイル転送進捗表示
- **進捗の非秘匿**: 転送済バイト数 (`transfer-bytes`) および総バイト数 (`transfer-total`) はメタデータとして扱い、UI 表示を許可。AEAD で保護されるべき本文 / 鍵 / IV とは異なるカテゴリ。
- **ローカル限定**: 進捗値は GUI プロセス内のローカル状態のみで保持され、`tokio::sync::mpsc::channel(1)` 経由で UI スレッドに転送される。**ネットワーク経由で peer に送信されない**。
- **信頼境界**: 送信側の `total_bytes` は `tokio::fs::metadata().len()` で取得した**ローカル FS 値**を信頼。受信側の `total_bytes` は受信中に確定しない (chunk 単位 AEAD frame で逐次到着) ため `None` 扱い、進捗バーは indeterminate animation で表示。peer が偽装した chunk header (chunk_len) は AEAD 認証 + `MAX_FILE_SIZE` 上限で検出され、転送 Error となる。
- **DoS 対策**: 進捗 callback の発火頻度は `PROGRESS_CHUNK_BYTES = 64 KiB` を threshold とした chunk counter ベースで制限。1 回の `try_send` で `mpsc::channel(1)` が full の場合は **新規発火を drop** (latest-wins semantic) し、UI スレッドが処理しきれない高速転送でも back-pressure せず、UI thread の hang を防止。
- **One-shot pump task**: `make_progress_pipeline` が返す `JoinHandle` は転送終了時に `abort()` され、未消費の channel エントリ + pump task が即時 drop される。abort は idempotent で再発火耐性あり。

## 1.11 F13: Chat メッセージモデルの上限 (peer がレートを決める DoS 対策)
チャット行の供給元は peer が書いた平文 (`chat_loop` → `GuiStdout` → `stdout_rx`) であり、行数・1 行の長さ・到着レートはいずれも peer 側が決める。以下の 4 つを個別に上限で押さえる。

- **行数上限**: `messages` モデルが保持するのは最大 `gui::MAX_CHAT_ROWS = 1000` 行。超過時は**最も古い行から破棄** (ring)。上限が無いと peer だけでこのプロセスの保持ヒープを決められた。1000 行は実運用の会話量 (1 時間の密なやり取りでも 100 行未満) に対して十分な余裕があり、全行が下記の長さ上限一杯でも保持量は約 1 MB。
- **1 行あたりの長さ上限**: peer 本文は `gui::format_chat_row` で `utils::sanitize_for_terminal_bounded(.., 256)` を通してから行にする。チャットパケットは最大 70000 byte (`network` の `chunk_len` 上限) で、従来はその全量が 1 行の `SharedString` になっていた。256 文字は scp / forward など他の peer 文字列 sink と同じ house 上限。超過分は `…[truncated]` マーカー付きで切られるので、切り詰めがユーザから見える。`chat_loop` 側の control/bidi フィルタは長さを一切制限しないため、長さの境界はこの 1 箇所のみ (異なる二重の上限は掛けない)。なお sanitize は残った `\n` / `\t` を空白に置換する (1 パケット = 1 リスト項目のため) 点が CLI 表示との差分。
- **UI スレッドの計算量**: 追記は `VecModel` への in-place `push` / `remove(0)`。従来はメッセージ 1 通ごとに既存全行を新しい `VecModel` にコピーし直して `set_messages` していたため、N 通で O(N^2) の行コピーが UI スレッド上で発生し、event loop が停止した。
- **event loop queue の深さ**: `slint::invoke_from_event_loop` のキューは無制限なので、パケット 1 個につき closure 1 個を投げない。行は `gui::ChatRowQueue` に staging し、**未処理の closure は同時に最大 1 個**とする (pending 中に届いた行はその closure がまとめて回収)。staging バッファ自体も `MAX_CHAT_ROWS` 上限を持つ。
- **表示上の帰結**: 1000 行を超えると古いメッセージは画面から消える (GUI にスクロールバック保存は無い)。256 文字を超えるメッセージは末尾が `…[truncated]` になり、GUI 側で全文は復元できない。

## 1.12 MLS グループチャット窓 (`gui-mls`) の Messages モデル
`GroupChatWindow` の Messages ペインは `ChatWindow` と同じ `StandardListView` + `StandardListViewItem` であり、行の供給元も同じく peer が書いた平文 (`accept_next` → `render_event`) である。§1.11 の 4 つの上限をこの窓にもそのまま適用する。定数 (`gui::MAX_CHAT_ROWS` / `gui::MAX_CHAT_ROW_CHARS`) と staging 実装 (`gui::ChatRowQueue`) は 1:1 窓と共有し、Slint がコンポーネントごとに別の型を生成するため `append_chat_rows` の本体だけを `append_message` として再掲する。

- **サニタイズ**: メンバ本文は `utils::sanitize_for_terminal_bounded(.., 256)` を `render_event` 内で通す (CLI 双子 `group::cli::render_event` と同じ位置 = 全呼出元をカバー)。Messages ペインには `[joined]` / `[epoch]` / `[removed]` という**信頼判断に使う行**が同居するため、本文に改行や bidi override を入れられると隣の行を偽造できる。なお `StandardListViewItem` は端末ではないので ESC / `\r` によるカーソル操作は無効 (Slint の `Text` は解釈せず描画するだけ) だが、bidi override / isolate による**行内の並べ替え**とゼロ幅文字による隠蔽は媒体が変わっても成立する。改行は行が固定高さ・非 wrap・`overflow: elide` の 1 行であるため、隣接行への描画か本文後半の黙殺かのいずれかになり、どちらも偽造プリミティブ。よって空白置換が正しい。
- **行数上限**: `append_message` が `MAX_CHAT_ROWS = 1000` で最古行から破棄。`push_event_into_ui` (peer 由来) と `wire_send_message` のローカルエコーの**両方**がこの関数を通るため、上限を迂回する行の供給路は無い。
- **UI スレッドの計算量**: `VecModel` への in-place `push` / `remove(0)`。従来は 1 通ごとに全行コピー + `set_messages` で O(N^2)。`row_data` は `unwrap` ではなく `filter_map` で受ける。
- **event loop queue の深さ**: 受信イベントは `ChatRowQueue` に staging し、未処理 closure は同時に最大 1 個。
- **表示上の帰結**: §1.11 と同じ。1000 行を超えた古い行は消え、256 文字を超えた本文は `…[truncated]` で切られる。`[leaf N @ <group-id>]` の接頭辞は自前の文字列なので上限の対象外。
