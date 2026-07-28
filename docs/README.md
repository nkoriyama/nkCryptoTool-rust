# docs/ — ドキュメント分類

root には一次文書のみを置く（[README](../README.md) / [USAGE](../USAGE.md) /
[SPEC](../SPEC.md) / [SECURITY](../SECURITY.md) / [KNOWN_ISSUES](../KNOWN_ISSUES.md) /
CHANGELOG）。それ以外は用途別に本フォルダへ分類する。

| フォルダ | 中身 | 性質 |
|---|---|---|
| [guides/](./guides/) | P2P ssh・チャット・鍵ローテーション・rsync 連携デプロイ・Android ビルド・再現ビルドの運用ガイド | 生きた文書（機能に追従して更新） |
| [security/](./security/) | セキュリティ評価（SECURITY_PROFILE / GUI 版）と監査対応記録（[2026-07 Claude Security](./security/AUDIT_2026-07_REMEDIATION.md)） | 生きた文書＋記録 |
| [reports/](./reports/) | 実装後の検証レポート・比較・エビデンス | 記録（時点スナップショット） |
| [design/](./design/) | 実装済み設計文書のアーカイブ（[索引](./design/README.md)） | 歴史（root の仕様文書が正） |
| [demos/](./demos/) | デモ GIF（`demos/*.tape` の出力先） | 生成物 |
