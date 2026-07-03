# P2P ファイル転送の比較

NAT/CGNAT 配下のホストへ「踏み台なし・ポート開放なし」でファイルを送受する各手段の比較。
対話シェル/到達手段そのものの比較は [`P2P_SHELL_COMPARISON.md`](./P2P_SHELL_COMPARISON.md)、
ZTNA / egress 制御下の可用性は [`ZTNA_AVAILABILITY.md`](./ZTNA_AVAILABILITY.md)。

> 本表は**設計説明**。nkCryptoTool 側の数値・挙動は本セッションで実測・検証済み
> （[`P2P_SCP_PIPELINE_REPORT.md`](./P2P_SCP_PIPELINE_REPORT.md) /
> [`P2P_INTEROP_EVIDENCE.md`](./P2P_INTEROP_EVIDENCE.md) §2.4）。**競合ツールのセルは
> 一般に知られた設計レベルの要約**であり、本リポジトリでベンチしたものではない（版・構成で
> 変わりうる。要検証）。

| ツール | P2P純度 | 到達（NAT越え） | 暗号・量子耐性 | 認可（誰が何を） | インストール | 中継依存 | 多数小ファイル | 主な強み | 弱み |
|---|---|---|---|---|---|---|---|---|---|
| **nkCryptoTool scp（yours）** | ★★★★★ Iroh ホールパンチ | 踏み台/ポート開放なし | ML-KEM-768＋ML-DSA-65 相互認証・AES-256-GCM（E2E・**量子耐性 ◎**）※1 | **指紋単位の read/write ルート＋パス confinement**・ファイル毎に認証付きアトミックコミット ※2 | バイナリ1つ | 自己ホスト relay 可（直結が既定） | ○ 1接続バッチ＋パイプライン（~0.5ms/file）※3 | 量子耐性・純P2P・サーバ側認可/監査・踏み台不要 | 開発中。bulk はユーザ空間QUICで ssh scp の ~0.4倍（WANでは網律速で不可視）※4 |
| scp / rsync over SSH | ★（要 reachable sshd） | 踏み台/ProxyJump 前提 | OpenSSH 9.x で PQC KEX 可・署名は古典 | Unix 権限＋sshd 設定 | 標準 | − | scp -r=△（per-file やや重）／rsync=◎（差分転送） | 成熟・ubiquitous・rsync の差分同期 | NAT 配下は踏み台/ポート開放が要る |
| magic-wormhole | ★★★（transit は直結試行→relay） | コード（PAKE）交換 | 古典（PQC でない） | なし（コード知る者） | 要 Python | 既定で relay にフォールバック | 通常 tar で1本化して送る | 短いコードで手軽な一回渡し | 常駐サーバ/認可なし・PQC でない |
| croc | ★★★（LAN 直結・既定は relay） | コード（PAKE）交換 | 古典（PQC でない） | なし（コード知る者） | 単一バイナリ | 既定で croc relay 経由 | 通常 tar で1本化して送る | クロスプラットフォーム・簡単 | 公開 relay 依存（自己ホスト可）・PQC でない |
| sendme（iroh） | ★★★★★ Iroh | チケット交換 | iroh トランスポート暗号（古典系）・BLAKE3 検証 | なし（チケット持つ者） | 自己ホスト relay 可 | collection を1転送 | ○ collection を1転送 | nkct と同系トランスポート・BLAKE3 検証 | アプリ層 PQC 認証なし・指紋単位の read/write 認可なし |

## 脚注

- **※1 暗号**: アプリ層で ML-KEM-768（P-256 とのハイブリッド）＋ ML-DSA-65 相互認証の AEAD を
  QUIC トランスポート上に重ねる。QUIC 自体の TLS は古典なので、**ポスト量子の機密性/認証は
  アプリ層 AEAD が担う**（＝二重暗号は PQC の代償。詳細 `P2P_SCP_DESIGN.md`）。
- **※2 認可**: `--scp-policy` で指紋ごとに read/write ルートを default-deny で与え、各パスを
  ルート配下に confine（`..`/絶対/symlink escape を封じ、Linux は `/proc/self/fd` で open 後
  再検証）。受信は O_NOFOLLOW|0600 の temp にステージし、**認証（AEAD タグ）が通った時だけ**
  fchmod（setuid/setgid 除去）→アトミック rename。tar-stream 型ツールにはない**サーバ側の
  ファイル毎認可・認証付きコミット**。
- **※3 多数小ファイル**: 以前は `put -r` がファイル毎に ack を待つ直列送信で per-file 1 RTT の
  待ちが乗り、多数小ファイルが遅かった。**パイプライン化（送信と ack 回収を並行）でこれを解消**
  し、VPS 実測で 400 ファイルが直列 ~3.6s → ~2.0s（44% 短縮、転送部分 ~9倍、~0.5ms/file）。
  ＝ tar で1本化して送るツール（wormhole/croc）や sendme の collection 転送と**同等水準**に達した
  （「負けていた弱点の解消」であって優越の主張ではない）。効果は「ファイル数 × RTT」に比例。
- **※4 bulk スループット**: loopback+tmpfs（CPU 律速）で ~643 MB/s、OpenSSH scp ~1700 MB/s。
  差の主因は**カーネル TCP vs ユーザ空間 QUIC**（二重暗号は AES-NI 天井 ~23GB/s で誤差、コピー
  最適化 +7% 回収済）。**WAN 実用途では網律速で差は見えない**（両者とも数十〜数百 Mbps の
  リンクを飽和）。接続確立は逆に OpenSSH の ~4 倍軽い（17ms vs 73ms、PQC ハンドシェイク込み）。

## 位置づけ

- **他ツールが持たないもの**: ポスト量子の E2E 認証・暗号、サーバ側の**指紋単位 read/write
  認可＋パス confinement**、ファイル毎の**認証付きアトミックコミット**、そして踏み台なしの
  純 P2P 到達を単一バイナリで。croc/wormhole は「手軽な一回渡し」、rsync は「差分同期」、
  sendme は「iroh blob 転送」に強いが、いずれもサーバ側の細粒度認可や PQC 認証は持たない。
- **弱み（正直に）**: 単一大ファイルの CPU 律速スループットは ssh scp に劣る（WAN では不可視）。
  差分転送（rsync 相当）は未対応。並列ストリーム（多数小ファイルをさらに速く）は nonce 分割が
  要るため保留。
