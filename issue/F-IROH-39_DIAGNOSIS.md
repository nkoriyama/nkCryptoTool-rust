# F-IROH-39 診断と修正方針 — chat_loop の stdin EOF 無限ループ

作成日: 2026-05-06
分類: Critical bug (production で CPU 100%)
発見経緯: 2026-05-06 の Iroh chat 実機動作テストにて (`client.log` が 2.5MB 超に膨張)

---

## 症状

- ユーザが `Ctrl-D` を押す / SSH セッション切断 / `cmd | nkct ...` のパイプ完了 等で stdin が EOF に到達した瞬間、chat_loop が tight loop に陥る
- CPU 100% を 1 コア占有
- stdout に `> ` が秒間数十万回出力 (実機計測で 2.5MB / 数秒)
- 影響範囲: **TCP / Iroh 両トランスポートの `chat_loop`** (汎用関数のため)

---

## 根本原因

`src/network/mod.rs:73-98` の `read_line_secure` が、**EOF と「空行入力」を同じ戻り値 `Ok(0)` で表現している**。

```rust
pub async fn read_line_secure<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<usize> {
    let mut b = [0u8; 1];
    let mut total = 0;
    const MAX_LINE_LEN: usize = 65536;
    loop {
        match reader.read(&mut b).await {
            Ok(0) => return Ok(total),       // ← EOF: total は 0 のまま
            Ok(1) => {
                if b[0] == b'\n' {
                    return Ok(total);         // ← 改行: total が 0 のこともある
                }
                if b[0] != b'\r' {
                    if total >= MAX_LINE_LEN {
                        return Err(CryptoError::Parameter("Line too long".to_string()));
                    }
                    buf.push(b[0]);
                    total += 1;
                }
            }
            _ => return Err(CryptoError::FileRead("Unexpected read result".to_string())),
        }
    }
}
```

`Ok(0)` を返す経路が 2 つ:

| 入力 | 経路 | 戻り値 | total |
|---|---|---|---|
| EOF (0 バイト読んだ後) | `Ok(0) =>` | `Ok(0)` | 0 |
| `\n` のみ (空行 Enter) | `b[0] == b'\n'` | `Ok(0)` | 0 |

呼び出し側 `chat_loop` (`mod.rs:420-426`):

```rust
res = Self::read_line_secure(&mut stdin, &mut line_buf) => {
    res?;
    if line_buf.is_empty() {
        let mut stdout = tokio::io::stdout();
        let _ = stdout.write_all(b"> ").await;
        let _ = stdout.flush().await;
        continue;       // ← EOF でも空行でも同じ扱い
    }
```

EOF 後は `tokio::io::stdin().read()` が **non-blocking で `Ok(0)` を即返す**ため、`select!` が即発火 → `continue` → 即発火 → 無限の tight loop。

---

## エッジケース整理

修正設計時に区別すべき 4 ケース:

| 入力 | 期待挙動 | 現状 |
|---|---|---|
| EOF (0 バイト) | chat_loop を抜ける | infinite loop ❌ |
| 空行 (`\n`) | プロンプト再表示で継続 | 継続 ✅ |
| 改行なし partial line + EOF (`"hello"<EOF>`) | 「メッセージ送信→切断」か「破棄→切断」 (設計判断) | `Ok(5)` で送信される (たぶん意図通り) |
| CRLF (`\r\n`) | 改行と同等 | 既存挙動 OK |

---

## 修正方針の選択肢

### 方針 A: `Result<Option<usize>>` で EOF を `None` に
最小変更:

```rust
pub async fn read_line_secure<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<usize>> {       // ← 戻り値変更
    let mut b = [0u8; 1];
    let mut total = 0;
    let mut got_any_byte = false;
    const MAX_LINE_LEN: usize = 65536;
    loop {
        match reader.read(&mut b).await {
            Ok(0) => {
                if got_any_byte {
                    return Ok(Some(total));   // partial line + EOF: 一行として処理
                } else {
                    return Ok(None);          // 純粋 EOF: caller に通知
                }
            }
            Ok(1) => {
                got_any_byte = true;
                if b[0] == b'\n' {
                    return Ok(Some(total));
                }
                // ... 既存ロジック ...
            }
            _ => return Err(...),
        }
    }
}
```

caller 側:

```rust
res = Self::read_line_secure(&mut stdin, &mut line_buf) => {
    let n = res?;
    if n.is_none() {
        eprintln!("\r\n[System]: stdin closed.");
        break Ok(());      // chat_loop 終了
    }
    if line_buf.is_empty() {
        // 空行 → プロンプト再表示
        ...
        continue;
    }
    // ... メッセージ送信 ...
}
```

**メリット**: 既存の使用箇所 (TCP / Iroh 両方) を最小変更で対応可能。`?` の挙動も維持。
**デメリット**: 戻り値の意味が複雑 (None=EOF, Some(0)=空行, Some(n)=n バイトの行)。

### 方針 B: 専用 enum 導入
意味論を明示:

```rust
pub enum LineRead {
    Line,           // 改行で終わる行 (空行を含む)
    PartialEof,     // 改行なしで EOF (partial line, buf に内容あり)
    Eof,            // バイト 0 個で EOF
}

pub async fn read_line_secure<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<LineRead> {
    // ...
}
```

caller 側:

```rust
res = Self::read_line_secure(&mut stdin, &mut line_buf) => {
    match res? {
        LineRead::Eof => break Ok(()),
        LineRead::PartialEof => {
            // 最後の入力を送って終了
            // ... 送信処理 ...
            break Ok(());
        }
        LineRead::Line if line_buf.is_empty() => {
            // 空行 → プロンプト再表示
            continue;
        }
        LineRead::Line => {
            // ... 通常メッセージ送信 ...
        }
    }
}
```

**メリット**: 各ケースの意図が明示的。エッジケース (partial line + EOF) も自然に扱える。
**デメリット**: 変更行数がやや増える。

### 方針 C: out-param で EOF フラグ
非推奨。Rust idiomatic でない。

### 方針 D: caller 側で「Ok(0) が連続したら EOF」と判定
**非推奨**。脆弱で false positive 余地あり (rapid Enter 連打を EOF と誤判定する可能性)。

### 推奨

**方針 B (enum)** が最も意図明確で、テスト可能性も高い。partial line + EOF の挙動 (送信 vs 破棄) は明示的に書ける。

---

## 検証用テストの設計

修正後の回帰防止のため、以下の **負例テスト** を `mod.rs` または `iroh.rs` に追加すべき:

### Test 1: chat_loop が EOF stdin で即終了する

```rust
#[tokio::test]
#[serial]
async fn test_chat_loop_exits_on_stdin_eof() {
    // mock stdin = tokio::io::empty()
    // mock stdout = tokio::io::sink() 
    // mock peer streams = duplex()
    let (mut peer_reader, peer_writer) = tokio::io::duplex(1024);
    let stdin = tokio::io::empty();           // 即 EOF
    let stdout = tokio::io::sink();
    
    let key = vec![0u8; 32];
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        chat_loop_with_io(stdin, stdout, peer_reader, peer_writer, "AES-256-GCM", &key, &key, false)
    ).await;
    
    assert!(result.is_ok(), "chat_loop must not hang on stdin EOF");
    assert!(result.unwrap().is_ok(), "should exit cleanly, not error");
}
```

ただしこのテストを書くには、**chat_loop が stdin/stdout を引数で受け取る形にリファクタ済み**である必要がある (現状は `tokio::io::stdin()` / `stdout()` をハードコード)。

### Test 2: 空行入力では継続する

```rust
#[tokio::test]
#[serial]
async fn test_chat_loop_continues_on_empty_line() {
    let stdin = std::io::Cursor::new(b"\n\n\nhello\n");  // 空行 3 連続後 "hello"
    // ... chat_loop を spawn し、peer 側に "hello" が届くことをアサート ...
}
```

---

## 関連リファクタリング機会

F-IROH-39 修正を機に、以下を一緒に整理するのが効率的:

1. **F-IROH-30 (chat_loop の真の E2E テスト不在)** — chat_loop を generic なリーダー/ライターに対する関数にリファクタすれば、本格的な E2E テストが書ける
2. **F-IROH-20 (`cfg!(test)` 混入)** — chat_loop と send_file/receive_file を引数で I/O を受け取る形にすれば、`cfg!(test)` shortcut が不要になる
3. **F-IROH-13 (`_s2c_iv` 未使用)** — chat_loop の双方向化や、partial line + EOF 後の最終送信時に活用余地

---

## 影響範囲の再確認

| 場面 | F-IROH-39 発症? | 重大度 |
|---|---|---|
| ユーザが `Ctrl-D` 押下 | YES | 🔴 |
| SSH セッション切断 | YES (stdin が close する) | 🔴 |
| `echo "hi" \| nkct --connect ...` (パイプ入力) | YES (stdin が EOF) | 🔴 |
| `nkct < input.txt --connect ...` (ファイル入力) | YES (ファイル末尾で EOF) | 🔴 |
| 通常のインタラクティブ使用 | NO | — |
| TUI / curses ベースの呼び出し | (依存) | △ |

→ **CLI ツールとして "Ctrl-D で抜けられない / パイプで使えない"** は最低限避けるべき UX。

---

## 推奨優先度

1. **即時**: 方針 B での `read_line_secure` リファクタ
2. **同時**: 検証用負例テスト (Test 1, Test 2) 追加
3. **検討**: F-IROH-30 / F-IROH-20 の解消も合わせて行うかどうか (chat_loop の I/O ジェネリック化)

修正自体は数十行のコード変更で済む見込み。テスト追加を含めても 1-2 時間程度の作業量。

---

## 関連ドキュメント

- `PHASE3_VERIFICATION_REPORT.md` — F-IROH-39 の発見経緯
- `IROH_MIGRATION_VERIFICATION_REPORT.md` — F-IROH-39 を理由に「完了」保留を推奨
- `IROH_MIGRATION_PLAN.md` — Phase 4 完了を主張する全体完了レポートの参照元
