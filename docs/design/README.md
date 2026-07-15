# docs/design — 実装済み設計文書のアーカイブ

設計フェーズで書かれ、**実装が main に取り込まれて役目を終えた**設計・計画文書の置き場。
歴史的経緯・設計判断の背景を調べるときに参照する。**現在の仕様・使い方は root の
[SPEC.md](../../SPEC.md) / [USAGE.md](../../USAGE.md) / [README.md](../../README.md) が正**
であり、本フォルダの文書と食い違う場合はそちらが優先される。

| 文書 | 主題 | 状態 |
|---|---|---|
| [KEY_EXCHANGE_DESIGN.md](./KEY_EXCHANGE_DESIGN.md) | 公開鍵授受 — ML-DSA 単一アンカーの KeyBundle (NKKB) | 実装済み（最終仕様に改稿済み） |
| [TRUST_BOOTSTRAP_DESIGN.md](./TRUST_BOOTSTRAP_DESIGN.md) | ペアリング（ssh-copy-id 相当）と二層信頼モデル | 実装済み |
| [P2P_SHELL_DESIGN.md](./P2P_SHELL_DESIGN.md) | 踏み台レス PQC P2P シェル / ポートフォワード | 実装済み |
| [P2P_SCP_DESIGN.md](./P2P_SCP_DESIGN.md) | P2P scp（nkct/scp/1、path confinement） | 実装済み |
| [PQFS_DESIGN.md](./PQFS_DESIGN.md) | Post-Quantum Forward Secrecy（One-Time Prekey） | 実装済み |
| [ATREST_ANTIROLLBACK_DESIGN.md](./ATREST_ANTIROLLBACK_DESIGN.md) | at-rest 暗号化とアンチロールバック | 実装済み |
| [DB_PURERUST_DESIGN.md](./DB_PURERUST_DESIGN.md) | SQLCipher → redb 純 Rust 化 | 実装済み |
| [MLS_GROUP_CHAT_PLAN.md](./MLS_GROUP_CHAT_PLAN.md) | MLS (RFC 9420) グループチャット実装計画 | 実装済み |
| [MLS_P2P_SYNC_DESIGN.md](./MLS_P2P_SYNC_DESIGN.md) | MLS↔P2P 同期（transport-gate 投影） | 一部撤回（commit 履歴・delta resync・NKCB binding は実装済み、gate 投影は撤回） |

- 実装後の**検証レポート・比較・エビデンス**（`*_REPORT.md` / `*_COMPARISON.md` /
  `P2P_INTEROP_EVIDENCE.md` 等）は現状の能力を示す生きた記録として root に残している。
- ソースコード内のコメントはファイル名（例 `PQFS_DESIGN.md §3.2`）で参照しており、
  本フォルダへ移動後もその名前で一意に見つかる。
